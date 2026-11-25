// The Aegis x402 signer: the enforcement point on the x402 rail.
//
// An x402 "exact" payment on Solana is a transaction the agent only partly
// signs: the facilitator adds the fee payer's signature and sends it. The money
// never passes through aegis_guard, so the guard can't see it. On this rail the
// irreversible act is producing our signature, and that is where Aegis stands.
//
// The agent is handed this signer instead of the key. It exposes `address`,
// `signTransactions` (kit's TransactionPartialSigner shape) and
// `signMessages`, and nothing that could sign around the checks:
//
//  - It decodes the exact bytes it will sign and trusts nothing else: not the
//    402, not the wrapper, not the scheme code that built the transaction.
//  - A payment is exactly [SetComputeUnitLimit, SetComputeUnitPrice,
//    TransferChecked, Memo], v0, no lookup tables, two signers: the fee payer
//    (never us) and us. Our key appears only as the transfer's authority, so no
//    Approve, SetAuthority, CloseAccount, System transfer or nonce advance can
//    ride along. The transfer is USDC on the classic Token program, 6 decimals,
//    from our own USDC account.
//  - Then it reads the chain from its own pinned RPC: the network, that the
//    blockhash is current (that is the only thing binding a Solana transaction
//    to a cluster), the destination account and who owns it, our balance. The
//    payee is the destination's owner, read now, and the full policy engine
//    (`aegisCheck`) must say PAY for it.
//  - Last, it simulates the exact transaction and requires that it moves
//    exactly `amount` of our USDC to the payee and nothing else.
//  - Raw message signing is refused unless it is an off-chain message
//    (`\xffsolana offchain`), which can never be a transaction.
//
// It bounds a prompt-injected agent, which can only act through the tools it is
// given. It does not stop a compromised process that reads the key from
// memory; the float's size is what bounds that. We don't claim otherwise.
import { createHash, createPrivateKey, KeyObject, sign as edSign } from "crypto";
import { Keypair, PublicKey } from "@solana/web3.js";

import { aegisCheck } from "../aegis";
import { DecodeError, decodeTokenAccount, TOKEN_ACCOUNT_LEN } from "../chain/decode";
import { describeError } from "../chain/confirm";
import { COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, USDC_DECIMALS, USDC_MINT, X402_NETWORK, caip2 } from "../config";
import { associatedTokenAddress } from "../guard/layout";
import { REFUSAL, RefusalCode } from "../refusals";
import { formatUnits } from "../units";
import { AegisPaymentRefused, OnRefuse, RefusalVerdict, fireRefusal } from "./refused";
import { SimulationResult, SvmRpc } from "./rpc";
import { DecodedMessage, decodeMessage, encodeTransaction, isWritable } from "./wire";

/** The reference client asks for 20,000; a transfer and a memo use about 13,000. */
export const MAX_COMPUTE_UNITS = 40_000;
/** The reference facilitator's own cap on the priority fee, which it pays. */
export const MAX_MICRO_LAMPORTS = 5_000_000n;
/** Decision 6: a memo is an invoice id (or our own 32-hex-character nonce). It is signed into the transaction verbatim. */
export const MEMO_RULE = /^[A-Za-z0-9_.:-]{1,64}$/;
/** The off-chain message signing domain. A message starting with 0xff can't be a transaction. */
export const OFFCHAIN_DOMAIN = Uint8Array.from([0xff, ...Buffer.from("solana offchain", "ascii")]);

export interface PolicyVerdict {
  decision: string;
  code: RefusalCode | null;
  reasons: string[];
}

/** The policy engine, for the payee the signer derived. Default: `aegisCheck`. */
export type PolicyCheck = (payTo: PublicKey, amountUnits: bigint, destination: PublicKey) => Promise<PolicyVerdict>;

/** kit's Transaction: the message bytes plus a signature slot per signer. */
export interface SignableTransaction {
  messageBytes: Uint8Array;
  signatures?: Record<string, Uint8Array | null>;
}

/** kit's SignableMessage. */
export interface SignableMessage {
  content: Uint8Array;
  signatures?: Record<string, Uint8Array | null>;
}

export type SignatureDictionary = Record<string, Uint8Array>;

export interface AegisSigner {
  readonly address: string;
  signTransactions(transactions: readonly SignableTransaction[]): Promise<SignatureDictionary[]>;
  signMessages(messages: readonly SignableMessage[]): Promise<SignatureDictionary[]>;
}

/** What the static decode proved about a payment message. */
export interface PaymentMessage {
  feePayer: PublicKey;
  source: PublicKey;
  destination: PublicKey;
  amount: bigint;
  blockhash: string;
  memo: string;
  computeUnits: number;
  microLamports: bigint;
}

export interface SignedPayment extends PaymentMessage {
  payTo: PublicKey;
  /** sha256 of the signed message, hex: the same payment re-signed has the same hash. */
  messageHash: string;
  signature: Uint8Array;
}

export interface SignerOptions {
  /** The pinned RPC every check reads from. */
  rpc: SvmRpc;
  /** The CAIP-2 network this signer pays on. Default: devnet. The RPC's genesis hash must match it. */
  network?: string;
  usdc?: PublicKey;
  /** Passed to the default policy check. undefined: from env/IDL (none found fails closed). */
  guard?: PublicKey | null;
  check?: PolicyCheck;
  /** Fired on every refusal. Must not throw and must not block (the audit logger is one). */
  onRefuse?: OnRefuse | null;
  /** Fired after each signature, for the run's own record. */
  onSign?: ((payment: SignedPayment) => void) | null;
  maxComputeUnits?: number;
  maxMicroLamports?: bigint;
}

// PKCS#8 wrapping for a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function privateKeyObject(keypair: Keypair): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(keypair.secretKey.subarray(0, 32))]), format: "der", type: "pkcs8" });
}

function refuse(code: RefusalCode, reason: string, about: { recipient?: string | null; amount?: bigint | null } = {}, verdict: RefusalVerdict = "BLOCK"): never {
  throw new AegisPaymentRefused(reason, verdict, { code, ...about });
}

const u32 = (b: Uint8Array, at: number) => Buffer.from(b).readUInt32LE(at);
const u64 = (b: Uint8Array, at: number) => Buffer.from(b).readBigUInt64LE(at);

/**
 * The static half: everything provable from the message bytes alone. Pure, so
 * it is tested byte by byte. Throws AegisPaymentRefused.
 */
export function checkPaymentMessage(
  messageBytes: Uint8Array,
  ctx: { us: PublicKey; usdc: PublicKey; maxComputeUnits?: number; maxMicroLamports?: bigint }
): PaymentMessage {
  const maxCu = ctx.maxComputeUnits ?? MAX_COMPUTE_UNITS;
  const maxPrice = ctx.maxMicroLamports ?? MAX_MICRO_LAMPORTS;
  const { us, usdc } = ctx;
  let m: DecodedMessage;
  try {
    m = decodeMessage(messageBytes);
  } catch (err) {
    return refuse(REFUSAL.MALFORMED_TRANSACTION, `the transaction message could not be decoded (${describeError(err)}).`);
  }
  if (m.version !== 0) refuse(REFUSAL.MALFORMED_TRANSACTION, "it is a legacy message; an x402 payment is a v0 message.");
  if (m.lookups.length > 0) refuse(REFUSAL.MALFORMED_TRANSACTION, "it loads accounts from address lookup tables, which can hide what it touches.");
  const keys = m.staticKeys;
  // First, since being fee payer also collapses the two signers into one.
  if (keys[0].equals(us)) refuse(REFUSAL.FEE_PAYER_IS_US, "it makes us the fee payer: we would pay the network fee and whatever priority fee it sets.");
  if (m.header.numRequiredSignatures !== 2) {
    refuse(REFUSAL.MALFORMED_TRANSACTION, `it needs ${m.header.numRequiredSignatures} signatures; a payment needs exactly 2 (the fee payer, then us).`);
  }
  if (!keys[1].equals(us)) refuse(REFUSAL.MALFORMED_TRANSACTION, "we are not its second signer.");
  if (m.instructions.length !== 4) {
    refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `it has ${m.instructions.length} instructions; a payment is exactly 4 (compute limit, compute price, TransferChecked, Memo).`);
  }
  const [limitIx, priceIx, transferIx, memoIx] = m.instructions;

  // Our key may appear once, as the transfer's authority; the fee payer, never.
  m.instructions.forEach((ix, i) => {
    if (ix.programIdIndex < 2) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `instruction ${i + 1} calls a signer as a program.`);
    ix.accountIndexes.forEach((a, pos) => {
      if (a === 0) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `instruction ${i + 1} passes the fee payer as an account.`);
      if (a === 1 && !(ix === transferIx && pos === 3)) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `instruction ${i + 1} uses our key for something other than authorizing the transfer.`);
    });
  });
  const program = (ix: { programIdIndex: number }) => keys[ix.programIdIndex];

  if (!program(limitIx).equals(COMPUTE_BUDGET_PROGRAM) || limitIx.accountIndexes.length !== 0 || limitIx.data.length !== 5 || limitIx.data[0] !== 2) {
    refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "instruction 1 is not SetComputeUnitLimit.");
  }
  const computeUnits = u32(limitIx.data, 1);
  if (computeUnits === 0 || computeUnits > maxCu) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `it asks for ${computeUnits} compute units (allowed 1 to ${maxCu}).`);
  if (!program(priceIx).equals(COMPUTE_BUDGET_PROGRAM) || priceIx.accountIndexes.length !== 0 || priceIx.data.length !== 9 || priceIx.data[0] !== 3) {
    refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "instruction 2 is not SetComputeUnitPrice.");
  }
  const microLamports = u64(priceIx.data, 1);
  if (microLamports > maxPrice) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `it sets a compute price of ${microLamports} micro-lamports (cap ${maxPrice}).`);

  const tokenProgram = program(transferIx);
  if (tokenProgram.equals(TOKEN_2022_PROGRAM)) refuse(REFUSAL.WRONG_ASSET, "it pays through Token-2022; the USDC this signer pays is a classic SPL Token mint.");
  if (!tokenProgram.equals(TOKEN_PROGRAM)) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "instruction 3 is not a token transfer.");
  if (transferIx.data.length !== 10 || transferIx.data[0] !== 12) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "instruction 3 is not TransferChecked.");
  if (transferIx.accountIndexes.length !== 4) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "TransferChecked lists other than its 4 accounts.");
  const [srcI, mintI, dstI, authI] = transferIx.accountIndexes;
  if (authI !== 1) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "the transfer's authority is not us.");
  const mint = keys[mintI];
  if (!mint.equals(usdc)) refuse(REFUSAL.WRONG_ASSET, `it transfers mint ${mint.toBase58()}, not the pinned USDC ${usdc.toBase58()}.`);
  if (transferIx.data[9] !== USDC_DECIMALS) refuse(REFUSAL.WRONG_ASSET, `it states ${transferIx.data[9]} decimals; USDC has ${USDC_DECIMALS}.`);
  const amount = u64(transferIx.data, 1);
  const source = keys[srcI];
  const destination = keys[dstI];
  if (amount === 0n) refuse(REFUSAL.BAD_AMOUNT, "it transfers 0.", { amount });
  if (!source.equals(associatedTokenAddress(us, usdc))) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "it spends from an account other than our USDC account.", { amount });
  if (destination.equals(source)) refuse(REFUSAL.BAD_DESTINATION, "it pays our own USDC account.", { amount });

  if (!program(memoIx).equals(MEMO_PROGRAM) || memoIx.accountIndexes.length !== 0) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "instruction 4 is not a plain Memo.", { amount });
  let memo: string;
  try {
    memo = new TextDecoder("utf-8", { fatal: true }).decode(memoIx.data);
  } catch {
    return refuse(REFUSAL.BAD_MEMO, "its memo is not valid UTF-8.", { amount });
  }
  if (!MEMO_RULE.test(memo)) refuse(REFUSAL.BAD_MEMO, "its memo is not an invoice id (1 to 64 of A-Z a-z 0-9 _ . : -). The memo is signed into the transaction verbatim.", { amount });

  // Exactly the accounts a payment uses: nothing extra, and the transfer's two
  // token accounts are the only writable ones besides the fee payer.
  const expected = new Set([keys[0], us, source, destination, mint, COMPUTE_BUDGET_PROGRAM, TOKEN_PROGRAM, MEMO_PROGRAM].map((k) => k.toBase58()));
  if (keys.length !== expected.size || keys.some((k) => !expected.has(k.toBase58()))) {
    refuse(REFUSAL.UNEXPECTED_INSTRUCTION, "it lists accounts the payment doesn't use.", { amount });
  }
  keys.forEach((k, i) => {
    const shouldWrite = i === 0 || k.equals(source) || k.equals(destination);
    if (isWritable(m, i) !== shouldWrite) refuse(REFUSAL.UNEXPECTED_INSTRUCTION, `it marks ${k.toBase58()} ${shouldWrite ? "read-only" : "writable"}.`, { amount });
  });

  return { feePayer: keys[0], source, destination, amount, blockhash: m.recentBlockhash, memo, computeUnits, microLamports };
}

interface ReadToken {
  owner: PublicKey;
  amount: bigint;
}

/** A classic-Token USDC account, or why it isn't one. */
function readUsdcAccount(acct: { owner: PublicKey; data: Buffer } | null, usdc: PublicKey): ReadToken | string {
  if (!acct) return "does not exist";
  if (!acct.owner.equals(TOKEN_PROGRAM)) return "is not a classic SPL Token account";
  if (acct.data.length !== TOKEN_ACCOUNT_LEN) return `has ${acct.data.length} bytes, not a token account's ${TOKEN_ACCOUNT_LEN}`;
  let t;
  try {
    t = decodeTokenAccount(acct.data);
  } catch (e) {
    return `could not be decoded (${e instanceof DecodeError ? e.message : describeError(e)})`;
  }
  if (t.state === "uninitialized") return "is not initialized";
  if (!t.mint.equals(usdc)) return `holds mint ${t.mint.toBase58()}, not USDC`;
  return { owner: t.owner, amount: t.amount };
}

/** Token deltas by (owner, mint), from a simulation. null when a field is missing. */
export function tokenDeltas(sim: SimulationResult): Map<string, bigint> | null {
  if (!sim.preTokenBalances || !sim.postTokenBalances) return null;
  const out = new Map<string, bigint>();
  for (const [list, sign] of [
    [sim.preTokenBalances, -1n],
    [sim.postTokenBalances, 1n],
  ] as const) {
    for (const b of list) {
      if (!b.owner) return null;
      const key = `${b.owner}:${b.mint}`;
      out.set(key, (out.get(key) ?? 0n) + sign * BigInt(b.amount));
    }
  }
  return out;
}

export function createAegisSigner(keypair: Keypair, opts: SignerOptions): AegisSigner {
  const us = keypair.publicKey;
  const key = privateKeyObject(keypair);
  const { rpc } = opts;
  const network = opts.network ?? X402_NETWORK;
  const usdc = opts.usdc ?? USDC_MINT;
  const check: PolicyCheck =
    opts.check ?? ((payTo, amountUnits, destination) => aegisCheck(payTo, formatUnits(amountUnits), { reader: rpc.reader, guard: opts.guard, destination, usdcMint: opts.usdc }));
  let networkChecked: Promise<void> | null = null;

  /** Reads fail closed: "could not read" is never "fine". */
  async function read<T>(what: string, f: () => Promise<T>, about: { recipient?: string | null; amount?: bigint | null }): Promise<T> {
    try {
      return await f();
    } catch (err) {
      return refuse(REFUSAL.LANE_UNAVAILABLE, `could not read ${what} from our RPC (${describeError(err)}), so nothing is known.`, about, "ASK_HUMAN");
    }
  }

  function assertNetwork(): Promise<void> {
    if (!networkChecked) {
      networkChecked = (async () => {
        const genesis = await read("the genesis hash", () => rpc.genesisHash(), {});
        if (caip2(genesis) !== network) {
          refuse(REFUSAL.WRONG_NETWORK, `our RPC is on ${caip2(genesis)}, not ${network}; the blockhash it vouches for would bind the payment to the wrong network.`);
        }
      })();
      // A read failure is retried next time; a wrong network is remembered.
      networkChecked.catch((err) => {
        if (err instanceof AegisPaymentRefused && err.code === REFUSAL.LANE_UNAVAILABLE) networkChecked = null;
      });
    }
    return networkChecked;
  }

  async function signOne(tx: SignableTransaction): Promise<SignatureDictionary> {
    const bytes = tx?.messageBytes;
    if (!(bytes instanceof Uint8Array)) refuse(REFUSAL.MALFORMED_TRANSACTION, "there are no message bytes to check.");
    const p = checkPaymentMessage(bytes, { us, usdc, maxComputeUnits: opts.maxComputeUnits, maxMicroLamports: opts.maxMicroLamports });
    const amountAbout = { amount: p.amount };

    await assertNetwork();
    const current = await read("whether the blockhash is current", () => rpc.isBlockhashValid(p.blockhash), amountAbout);
    if (!current) refuse(REFUSAL.VALIDITY_WINDOW, "its blockhash is not current on our RPC: it has expired, or it comes from another cluster.", amountAbout);

    const [dstAcct, srcAcct] = await read("the payment's token accounts", () => rpc.reader.getAccounts([p.destination, p.source]), amountAbout);
    const dst = readUsdcAccount(dstAcct, usdc);
    if (typeof dst === "string") refuse(REFUSAL.BAD_DESTINATION, `the destination ${p.destination.toBase58()} ${dst}.`, amountAbout);
    const payTo = dst.owner;
    const about = { recipient: payTo.toBase58(), amount: p.amount };
    if (payTo.equals(us)) refuse(REFUSAL.BAD_DESTINATION, "the destination is our own account.", about);
    if (!p.destination.equals(associatedTokenAddress(payTo, usdc))) {
      refuse(
        REFUSAL.DESTINATION_OWNER_MISMATCH,
        `the destination ${p.destination.toBase58()} is not its owner's associated USDC account: its owner was reassigned, or it never was one.`,
        about
      );
    }
    const src = readUsdcAccount(srcAcct, usdc);
    if (typeof src === "string") refuse(REFUSAL.EXCEEDS_BALANCE, `our USDC account ${src}.`, about);
    if (src.amount < p.amount) {
      refuse(REFUSAL.EXCEEDS_BALANCE, `it pays ${formatUnits(p.amount)} USDC and our wallet holds ${formatUnits(src.amount)}.`, about);
    }

    // The policy engine, on the payee read from the chain, not the one a 402 named.
    let verdict: PolicyVerdict;
    try {
      verdict = await check(payTo, p.amount, p.destination);
    } catch (err) {
      return refuse(REFUSAL.LANE_UNAVAILABLE, `the policy check failed (${describeError(err)}).`, about, "ASK_HUMAN");
    }
    if (verdict.decision !== "PAY") {
      refuse(
        verdict.code ?? REFUSAL.UNKNOWN,
        `verdict ${verdict.decision} on ${payTo.toBase58()}${verdict.reasons?.length ? ` - ${verdict.reasons[0]}` : ""}`,
        about,
        verdict.decision === "ASK_HUMAN" ? "ASK_HUMAN" : "BLOCK"
      );
    }

    // Last, the exact transaction, simulated: it must move exactly this payment.
    const sim = await read("a simulation of the payment", () => rpc.simulate(encodeTransaction([new Uint8Array(64), new Uint8Array(64)], bytes)), about);
    const mismatch = (why: string) => refuse(REFUSAL.SIMULATION_MISMATCH, `simulating it ${why}.`, about);
    if (sim.err !== null) mismatch(`failed: ${JSON.stringify(sim.err)}`);
    if (!sim.unitsConsumed) mismatch("reported no compute used");
    const deltas = tokenDeltas(sim);
    if (!deltas) mismatch("did not report token balance changes, so they can't be checked");
    const want = new Map([
      [`${us.toBase58()}:${usdc.toBase58()}`, -p.amount],
      [`${payTo.toBase58()}:${usdc.toBase58()}`, p.amount],
    ]);
    for (const [k, v] of deltas!) if (v !== (want.get(k) ?? 0n)) mismatch(`moves ${v} of ${k.split(":")[1]} for ${k.split(":")[0]}`);
    for (const [k, v] of want) if ((deltas!.get(k) ?? 0n) !== v) mismatch(`does not move ${v} of USDC for ${k.split(":")[0]}`);
    const accountCount = decodeMessage(bytes).staticKeys.length;
    for (const balances of [sim.preBalances, sim.postBalances]) {
      if (!Array.isArray(balances) || balances.length !== accountCount || Array.from(balances).some((n) => typeof n !== "number" || !Number.isFinite(n))) {
        mismatch("did not report a numeric SOL balance for every static account");
      }
    }
    if (sim.preBalances![1] !== sim.postBalances![1]) mismatch("changes our SOL balance");

    const signature = Uint8Array.from(edSign(null, Buffer.from(bytes), key));
    try {
      opts.onSign?.({ ...p, payTo, messageHash: createHash("sha256").update(bytes).digest("hex"), signature });
    } catch {
      // a broken log is not a reason to withhold a payment that cleared
    }
    return { [us.toBase58()]: signature };
  }

  async function guarded<T>(f: () => Promise<T>): Promise<T> {
    try {
      return await f();
    } catch (err) {
      const refusal =
        err instanceof AegisPaymentRefused
          ? err
          : new AegisPaymentRefused(`the signer hit an unexpected error (${describeError(err)}), so it signs nothing.`, "BLOCK", { code: REFUSAL.UNKNOWN });
      fireRefusal(opts.onRefuse, refusal);
      throw refusal;
    }
  }

  const signer: AegisSigner = {
    address: us.toBase58(),
    signTransactions: (transactions) =>
      guarded(async () => {
        // One payment per call: no reasoning about what several do together.
        if (!Array.isArray(transactions) || transactions.length !== 1) {
          refuse(REFUSAL.MALFORMED_TRANSACTION, "the signer takes exactly one payment transaction per call.");
        }
        return [await signOne(transactions[0])];
      }),
    signMessages: (messages) =>
      guarded(async () => {
        if (!Array.isArray(messages) || messages.length === 0) refuse(REFUSAL.DISABLED_PRIMITIVE, "there is no message to sign.");
        return messages.map((msg) => {
          const content = msg?.content;
          const offchain = content instanceof Uint8Array && content.length > OFFCHAIN_DOMAIN.length && OFFCHAIN_DOMAIN.every((b, i) => content[i] === b);
          if (!offchain) {
            refuse(REFUSAL.DISABLED_PRIMITIVE, "raw message signing is disabled: a raw Ed25519 signature can authorize a transaction. Only off-chain messages (\\xffsolana offchain) are signed.");
          }
          return { [us.toBase58()]: Uint8Array.from(edSign(null, Buffer.from(content), key)) };
        });
      }),
  };
  return Object.freeze(signer);
}

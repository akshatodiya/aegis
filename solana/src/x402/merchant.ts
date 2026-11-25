// The x402 merchant: the other side of the wire for the demo and the tests.
//
// A real HTTP server: the agent's requests cross a real socket, and the 402
// challenge and the payment header are real headers. Unlike the EVM mock, it
// settles: it acts as its own facilitator (fee payer = the merchant's key),
// which the SVM exact spec allows. So a payment it accepts really moves USDC on
// the cluster it is connected to (the local validator in tests, devnet in the
// demo).
//
// Before it co-signs anything it runs the facilitator's checks itself, with
// web3.js's decoder rather than the signer's, so the two sides don't share a
// misreading: v0, no lookup tables, two signers with us first, exactly the
// payment instructions, the fee payer in no instruction, the transfer to
// ATA(payTo) of exactly the demanded amount, the client's Ed25519 signature,
// a current blockhash, and a clean simulation.
//
// Order matters: the product response is prepared before settlement, so a
// preparation error never charges the payer. The callback must not perform
// external delivery; the response is sent only after settlement succeeds.
// The payment hash is reserved before preparation, so concurrent copies
// cannot start two product calls.
//
// It answers like the reference v2 resource server: it reads only
// PAYMENT-SIGNATURE; an unreadable header is a plain 402; a payment that fails
// a check is a 402 whose PAYMENT-REQUIRED carries the facilitator's error code;
// one that verified but didn't settle (a duplicate, a pending or failed
// settlement) is a 402 whose PAYMENT-RESPONSE says success:false and why. Two
// differences: the body repeats the header instead of being `{}`, and when the
// chain can't be read it answers 503 rather than blaming the payment.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, KeyObject } from "crypto";
import { createServer, IncomingMessage, Server, ServerResponse } from "http";
import { utils } from "@anchor-lang/core";
import { Connection, Keypair, PublicKey, SendTransactionError, VersionedTransaction } from "@solana/web3.js";

import { blockhashExpiry, describeError, followSignature } from "../chain/confirm";
import { COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, USDC_MINT } from "../config";
import { associatedTokenAddress } from "../guard/layout";
import { MAX_COMPUTE_UNITS } from "./signer";
import { decodeTransaction } from "./wire";

const LIGHTHOUSE = new PublicKey("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95");
const MAX_MICRO_LAMPORTS = 5_000_000n;
const MAX_HEADER_CHARS = 16_384;
/** How long a settled payment's hash is remembered. Its blockhash is dead well before this. */
const REPLAY_TTL_MS = 120_000;

export interface MerchantService {
  route: string;
  name: string;
  /** The wallet paid. Its USDC account must already exist: x402 exact never creates it. */
  payTo: PublicKey;
  /** Base units demanded in the 402. */
  demand: bigint;
  /** The asset the 402 names. Default USDC; the look-alike route names another mint. */
  asset?: PublicKey;
  /** An invoice id, signed into the payment's memo. */
  memo?: string;
  description?: string;
  mimeType?: string;
  /**
   * Prepare response data only. This runs before settlement: do not send
   * email, call a delivery webhook, or consume inventory here. The merchant
   * returns the prepared data only after the payment confirms.
   */
  product: unknown | ((url: URL) => unknown);
}

export interface MerchantOptions {
  connection: Connection;
  /** Pays the network fee for every settlement, and signs first. */
  feePayer: Keypair;
  /** CAIP-2 id of the cluster `connection` is on. */
  network: string;
  services: MerchantService[];
  log?: (msg: string) => void;
  /** How long to follow a settlement before answering "pending". */
  settleTimeoutMs?: number;
}

export interface Requirement {
  scheme: "exact";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: { feePayer: string; memo?: string };
}

const b64json = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString("base64");

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function privateKey(kp: Keypair): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(kp.secretKey.subarray(0, 32))]), format: "der", type: "pkcs8" });
}

export function verifyEd25519(signer: PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, signer.toBuffer()]), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
}

/**
 * The reference facilitator's failure codes, where it has one for the check.
 * The merchant puts the code in the 402's `error` and keeps the sentence for
 * its log.
 */
export const INVALID = {
  DECODE: "invalid_exact_svm_payload_transaction_could_not_be_decoded",
  SIGNERS: "invalid_exact_svm_payload_excessive_signers",
  FEE_PAYER: "invalid_exact_svm_fee_payer_not_managed_by_facilitator",
  FEE_PAYER_IN_IX: "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
  IX_COUNT: "invalid_exact_svm_payload_transaction_instructions_length",
  CU_LIMIT: "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
  CU_PRICE: "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
  CU_PRICE_HIGH: "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
  NO_TRANSFER: "invalid_exact_svm_payload_no_transfer_instruction",
  MINT: "invalid_exact_svm_payload_mint_mismatch",
  RECIPIENT: "invalid_exact_svm_payload_recipient_mismatch",
  AMOUNT: "invalid_exact_svm_payload_amount_mismatch",
  MEMO_COUNT: "invalid_exact_svm_payload_memo_count",
  MEMO: "invalid_exact_svm_payload_memo_mismatch",
  SIGNATURE: "invalid_exact_svm_payload_signature_invalid",
  SIMULATION: "invalid_exact_svm_transaction_simulation_failed",
  TX_FAILED: "invalid_exact_svm_transaction_failed",
  NO_MATCH: "No matching payment requirements",
  DUPLICATE: "duplicate_settlement",
  PENDING: "settlement_pending",
} as const;

const ORDINAL = ["fourth", "fifth", "sixth", "seventh"];

export type Verdict =
  | { ok: true; payer: PublicKey; messageBytes: Uint8Array; signatures: Uint8Array[] }
  /** status 402: the payment is bad; 503: we could not check it against the chain. */
  | { ok: false; status: 402 | 503; code: string; error: string };

/**
 * The facilitator's static checks plus the client's signature, a current
 * blockhash and a simulation. Never throws: a hostile payload gets a code, not
 * a crash.
 */
export async function verifyPayment(connection: Connection, wire: Uint8Array, req: Requirement, feePayer: PublicKey): Promise<Verdict> {
  const fail = (code: string, error: string): Verdict => ({ ok: false, status: 402, code, error });
  let tx: VersionedTransaction;
  let messageBytes: Uint8Array;
  let signatures: Uint8Array[];
  try {
    tx = VersionedTransaction.deserialize(wire);
    // Sign and settle the client's own bytes, never a re-encoding of them.
    ({ messageBytes, signatures } = decodeTransaction(wire));
    if (!Buffer.from(tx.message.serialize()).equals(Buffer.from(messageBytes))) return fail(INVALID.DECODE, "the transaction is not in canonical form");
  } catch (err) {
    return fail(INVALID.DECODE, `the transaction could not be decoded: ${describeError(err)}`);
  }
  const msg = tx.message;
  if (msg.version !== 0) return fail(INVALID.DECODE, "not a v0 transaction");
  if (msg.addressTableLookups.length > 0) return fail(INVALID.DECODE, "address lookup tables are not accepted");
  const keys = msg.staticAccountKeys;
  if (!keys[0].equals(feePayer)) return fail(INVALID.FEE_PAYER, "the fee payer is not ours");
  if (msg.header.numRequiredSignatures !== 2) return fail(INVALID.SIGNERS, "a payment has exactly two signers: our fee payer, then the payer");
  const ixs = msg.compiledInstructions;
  if (ixs.length < 3 || ixs.length > 7) return fail(INVALID.IX_COUNT, `${ixs.length} instructions; the exact scheme allows 3 to 7`);
  for (const ix of ixs) {
    if (ix.programIdIndex === 0 || ix.accountKeyIndexes.includes(0)) return fail(INVALID.FEE_PAYER_IN_IX, "the fee payer appears in an instruction");
  }
  const prog = (i: number) => keys[ixs[i].programIdIndex];
  const data = (i: number) => Buffer.from(ixs[i].data);
  if (!prog(0).equals(COMPUTE_BUDGET_PROGRAM) || data(0).length !== 5 || data(0)[0] !== 2) return fail(INVALID.CU_LIMIT, "instruction 1 is not SetComputeUnitLimit");
  if (data(0).readUInt32LE(1) > MAX_COMPUTE_UNITS) return fail(INVALID.CU_LIMIT, "the compute unit limit is over our cap");
  if (!prog(1).equals(COMPUTE_BUDGET_PROGRAM) || data(1).length !== 9 || data(1)[0] !== 3) return fail(INVALID.CU_PRICE, "instruction 2 is not SetComputeUnitPrice");
  if (data(1).readBigUInt64LE(1) > MAX_MICRO_LAMPORTS) return fail(INVALID.CU_PRICE_HIGH, "compute unit price over our cap");
  const tokenProgram = prog(2);
  if (!(tokenProgram.equals(TOKEN_PROGRAM) || tokenProgram.equals(TOKEN_2022_PROGRAM)) || data(2).length < 10 || data(2)[0] !== 12) {
    return fail(INVALID.NO_TRANSFER, "instruction 3 is not TransferChecked");
  }
  const accts = ixs[2].accountKeyIndexes;
  if (accts.length < 4) return fail(INVALID.NO_TRANSFER, "TransferChecked is missing accounts");
  const [, mint, destination, authority] = accts.map((i) => keys[i]);
  const asset = new PublicKey(req.asset);
  if (!mint.equals(asset)) return fail(INVALID.MINT, "the transfer is in another mint");
  if (!destination.equals(associatedTokenAddress(new PublicKey(req.payTo), asset, tokenProgram))) return fail(INVALID.RECIPIENT, "the transfer does not pay our associated token account");
  if (data(2).readBigUInt64LE(1) !== BigInt(req.amount)) return fail(INVALID.AMOUNT, `the transfer is for ${data(2).readBigUInt64LE(1)}, not the ${req.amount} demanded`);
  if (!authority.equals(keys[1])) return fail(INVALID.NO_TRANSFER, "the transfer's authority is not the payer");
  const memos: Buffer[] = [];
  for (let i = 3; i < ixs.length; i++) {
    if (prog(i).equals(MEMO_PROGRAM)) memos.push(data(i));
    else if (!prog(i).equals(LIGHTHOUSE)) return fail(`invalid_exact_svm_payload_unknown_${ORDINAL[i - 3]}_instruction`, `instruction ${i + 1} is not a Memo or Lighthouse instruction`);
  }
  if (req.extra.memo !== undefined) {
    if (memos.length !== 1) return fail(INVALID.MEMO_COUNT, `${memos.length} memos; our invoice needs exactly one`);
    if (memos[0].toString("utf8") !== req.extra.memo) return fail(INVALID.MEMO, "the memo is not our invoice id");
  }
  if (!verifyEd25519(keys[1], messageBytes, signatures[1])) return fail(INVALID.SIGNATURE, "the payer's signature does not verify against the transaction");
  try {
    const { value: current } = await connection.isBlockhashValid(msg.recentBlockhash, { commitment: "confirmed" });
    if (!current) return fail(INVALID.SIMULATION, "the transaction's blockhash has expired");
    const sim = await connection.simulateTransaction(tx, { sigVerify: false, replaceRecentBlockhash: false, commitment: "confirmed" });
    if (sim.value.err) return fail(INVALID.SIMULATION, `the transaction fails in simulation: ${JSON.stringify(sim.value.err)}`);
  } catch (err) {
    return { ok: false, status: 503, code: "chain_unavailable", error: `could not check the transaction against the chain: ${describeError(err)}` };
  }
  return { ok: true, payer: keys[1], messageBytes, signatures };
}

/** These extra fields change per challenge, so the client's copy of them is not compared. */
const DYNAMIC_EXTRA = new Set(["recentBlockhash", "lastValidBlockHeight"]);

/** JSON with object keys sorted, so key order never decides a match but types and values do. */
function canonical(v: unknown): string {
  const sorted = JSON.stringify(v, (_k, x) =>
    x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) : x
  );
  return sorted ?? "undefined";
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/**
 * Whether a v2 payload's `accepted` is the requirement we serve, as the
 * reference server decides it: every field we declared is deep-equal, and
 * `extra` may carry more keys but must keep ours (bar the dynamic ones).
 */
export function acceptedMatches(accepted: unknown, want: Requirement): boolean {
  if (!isRecord(accepted)) return false;
  for (const [k, v] of Object.entries(want)) {
    if (k === "extra") continue;
    if (!Object.prototype.hasOwnProperty.call(accepted, k) || canonical(accepted[k]) !== canonical(v)) return false;
  }
  const extra = accepted.extra;
  if (!isRecord(extra)) return false;
  for (const [k, v] of Object.entries(want.extra)) {
    if (DYNAMIC_EXTRA.has(k)) continue;
    if (!Object.prototype.hasOwnProperty.call(extra, k) || canonical(extra[k]) !== canonical(v)) return false;
  }
  return true;
}

export function createMerchant(opts: MerchantOptions): Server {
  const { connection, network, log = () => {} } = opts;
  const feePayer = opts.feePayer.publicKey;
  const feeKey = privateKey(opts.feePayer);
  const byRoute = new Map(opts.services.map((s) => [s.route, s]));
  // hash -> when it stopped being in flight (null while settling)
  const seen = new Map<string, number | null>();

  function requirement(svc: MerchantService): Requirement {
    return {
      scheme: "exact",
      network,
      amount: svc.demand.toString(),
      asset: (svc.asset ?? USDC_MINT).toBase58(),
      payTo: svc.payTo.toBase58(),
      maxTimeoutSeconds: 60,
      extra: { feePayer: feePayer.toBase58(), ...(svc.memo ? { memo: svc.memo } : {}) },
    };
  }

  function paymentRequired(svc: MerchantService, req: IncomingMessage, path: string, error?: string) {
    const sent = req.headers.host;
    const host = typeof sent === "string" && /^[\w.-]+(:\d+)?$/.test(sent) ? sent : "localhost";
    return {
      x402Version: 2,
      ...(error ? { error } : {}),
      resource: { url: `http://${host}${path}`, description: svc.description ?? svc.name, mimeType: svc.mimeType ?? "application/json" },
      accepts: [requirement(svc)],
    };
  }

  /** 402 with the requirements, and the reason the last payment didn't count if there was one. */
  function challenge(res: ServerResponse, svc: MerchantService, req: IncomingMessage, path: string, error?: string) {
    const doc = paymentRequired(svc, req, path, error);
    json(res, 402, doc, { "PAYMENT-REQUIRED": b64json(doc), "cache-control": "no-store" });
  }

  /** 402 after a payment verified but did not settle: the receipt says why, and names the transaction if one was sent. */
  function unsettled(res: ServerResponse, errorReason: string, errorMessage: string, payer: string, transaction = "") {
    const receipt = { success: false, errorReason, errorMessage, transaction, network, payer };
    json(res, 402, receipt, { "PAYMENT-RESPONSE": b64json(receipt), "cache-control": "no-store" });
  }

  function forget(now: number) {
    for (const [h, done] of seen) if (done !== null && now - done > REPLAY_TTL_MS) seen.delete(h);
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const svc = byRoute.get(url.pathname);
      if (!svc) return json(res, 404, { error: `no service at ${url.pathname}` });
      const header = req.headers["payment-signature"];
      if (!header) {
        log(`402 for ${url.pathname}: "${svc.name}" demands ${svc.demand} base units to ${svc.payTo.toBase58()}`);
        return challenge(res, svc, req, url.pathname);
      }

      // ---- a paid retry: check everything before serving or settling ----
      // A header we can't read is no payment at all: a plain 402, as the reference server does.
      let wire: Uint8Array;
      let payload: any;
      try {
        if (typeof header !== "string" || header.length > MAX_HEADER_CHARS) throw new Error("bad header");
        payload = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
        wire = Buffer.from(String(payload?.payload?.transaction ?? ""), "base64");
        if (wire.length === 0) throw new Error("no transaction");
      } catch {
        log(`unreadable payment header for ${url.pathname}; treating the request as unpaid`);
        return challenge(res, svc, req, url.pathname);
      }
      // The client must echo the requirement it is paying. Only v2 is served here.
      const want = requirement(svc);
      if (payload?.x402Version !== 2 || !acceptedMatches(payload.accepted, want)) {
        log(`refused a payment for ${url.pathname}: it does not accept this resource's requirement`);
        return challenge(res, svc, req, url.pathname, INVALID.NO_MATCH);
      }

      // A payment already settled or settling is a duplicate, said before any
      // chain check: once it has landed, a simulation would only call it failed.
      const hashOf = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
      forget(Date.now());
      try {
        const early = decodeTransaction(wire);
        if (seen.has(hashOf(early.messageBytes))) {
          return unsettled(res, INVALID.DUPLICATE, "this payment was already used", early.message.staticKeys[1]?.toBase58() ?? "");
        }
      } catch {
        // undecodable: verifyPayment says so with its code
      }

      const verdict = await verifyPayment(connection, wire, want, feePayer);
      if (verdict.ok === false) {
        if (verdict.code === INVALID.SIMULATION) {
          // A restart forgets `seen`. The fee payer's Ed25519 signature is the
          // transaction id, so ask the chain before calling an old payment bad.
          try {
            const old = decodeTransaction(wire);
            const signature = utils.bytes.bs58.encode(edSign(null, Buffer.from(old.messageBytes), feeKey));
            const status = (await connection.getSignatureStatuses([signature], { searchTransactionHistory: true })).value?.[0];
            if (status) {
              seen.set(hashOf(old.messageBytes), Date.now());
              return unsettled(res, INVALID.DUPLICATE, "this payment was already used", old.message.staticKeys[1]?.toBase58() ?? "");
            }
          } catch {
            // A failed status read leaves the simulation refusal in place.
          }
        }
        log(`refused a payment for ${url.pathname}: ${verdict.code}: ${verdict.error}`);
        if (verdict.status === 503) return json(res, 503, { error: verdict.error }, { "cache-control": "no-store" });
        return challenge(res, svc, req, url.pathname, verdict.code);
      }
      const payer = verdict.payer.toBase58();
      const hash = hashOf(verdict.messageBytes);
      const duplicate = () => unsettled(res, INVALID.DUPLICATE, "this payment was already used", payer);
      if (seen.has(hash)) return duplicate();
      seen.set(hash, null);

      // Prepare the response first. If preparation fails, nothing is settled
      // and the payer keeps a usable payment.
      let product: unknown;
      try {
        product = typeof svc.product === "function" ? await (svc.product as (u: URL) => unknown)(url) : svc.product;
      } catch (err) {
        seen.delete(hash);
        return json(res, 502, { error: `the service failed to produce its result: ${describeError(err)}` });
      }

      // ---- settle: co-sign as fee payer, send, follow ----
      const signatures = [Uint8Array.from(edSign(null, Buffer.from(verdict.messageBytes), feeKey)), verdict.signatures[1]];
      const full = Uint8Array.from([2, ...signatures[0], ...signatures[1], ...verdict.messageBytes]);
      const signature = utils.bytes.bs58.encode(signatures[0]);
      let sendError: unknown = null;
      try {
        await connection.sendRawTransaction(full, { skipPreflight: false, preflightCommitment: "confirmed" });
      } catch (err) {
        if (err instanceof SendTransactionError) {
          // The RPC refused it; it never left. The payer may try again.
          seen.delete(hash);
          return unsettled(res, INVALID.TX_FAILED, `settlement was rejected: ${describeError(err)}`, payer);
        }
        sendError = err;
      }
      const tx = VersionedTransaction.deserialize(full);
      const followed = await followSignature(connection, signature, blockhashExpiry(connection, tx.message.recentBlockhash), {
        timeoutMs: opts.settleTimeoutMs ?? 60_000,
        pollMs: 400,
        sendError,
      });
      if (followed.outcome === "unknown") {
        // It may still land, so the hash stays: the same payment can't be tried twice.
        seen.set(hash, Date.now());
        return unsettled(res, INVALID.PENDING, `settlement pending: ${followed.why}`, payer, signature);
      }
      if (followed.outcome === "expired") {
        seen.delete(hash);
        return unsettled(res, INVALID.TX_FAILED, `settlement did not land: ${followed.why}`, payer, signature);
      }
      seen.set(hash, Date.now());
      if (followed.err !== null) return unsettled(res, INVALID.TX_FAILED, `settlement failed on-chain: ${JSON.stringify(followed.err)}`, payer, signature);

      log(`settled ${svc.demand} base units from ${payer} for "${svc.name}": ${signature}`);
      const receipt = { success: true, transaction: signature, network, payer };
      return json(res, 200, { data: product, payment: { ...receipt, amount: svc.demand.toString() } }, { "PAYMENT-RESPONSE": b64json(receipt) });
    } catch (err) {
      // a bug here is a 500, never a crash of the merchant
      return json(res, 500, { error: `merchant error: ${describeError(err)}` });
    }
  });
}

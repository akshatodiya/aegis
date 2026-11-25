// Talks to the deployed aegis_guard program. `assess` is a read (simulated, no
// signature); `guardedPay` moves USDC out of the vault; `addEntry` /
// `removeEntry` are the owner's list writes. Keys are passed per call, never
// held: which process loads which key is the caller's decision (see the README).
//
// Every write is followed to a known end: succeeded, landed but failed (with
// skipPreflight a refused transaction still lands and pays its fee), never
// landed, or "could not tell", which is reported as such and never as "not sent".
import { AnchorProvider, BN, Program, utils } from "@anchor-lang/core";
import {
  Connection,
  Keypair,
  PublicKey,
  SendTransactionError,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import idl from "../../target/idl/aegis_guard.json";
import type { AegisGuard } from "../../target/types/aegis_guard";
import { blockHeightExpiry, describeError, fetchLogs, followSignature } from "../chain/confirm";
import { TOKEN_ACCOUNT_LEN, decodeTokenAccount } from "../chain/decode";
import { AccountReader, RawAccount, connectionReader } from "../chain/reader";
import { ATA_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM, USDC_MINT } from "../config";
import { RefusalCode, guardFailureCode, guardReasonCode } from "../refusals";
import { ConfigData, EntryKind, GuardPdas, accountDiscriminator, associatedTokenAddress, readConfig, readEntry } from "./layout";

const KIND_ARG: Record<EntryKind, object> = {
  agent: { agent: {} },
  deny: { deny: {} },
  allow: { allow: {} },
  blockprog: { blockProgram: {} },
  reporter: { reporter: {} },
};

export type OnchainVerdict = "PAY" | "REVIEW" | "BLOCK";

export interface OnchainAssessment {
  verdict: OnchainVerdict;
  /** The program's own reason, as the TS client names the enum variant (`denylisted`, `dailyCap`, ...). */
  reason: string;
  code: RefusalCode | null;
  spentToday: bigint;
  dailyLimit: bigint;
}

export interface SendOutcome {
  ok: boolean;
  signature: string | null;
  /**
   * true: the transaction reached the chain and paid its fee, even if it failed.
   * false: it never did. null: could not tell; check `signature` before retrying.
   */
  landed: boolean | null;
  code: RefusalCode | null;
  error: string | null;
  logs: string[];
}

// anchor-lang event.rs: EVENT_IX_TAG, little endian. A self-CPI event's data starts with it.
const EVENT_IX_TAG = Buffer.from([0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d]);

function checkRecipientAta(acct: RawAccount, address: PublicKey, recipient: PublicKey, mint: PublicKey) {
  if (acct.data.length !== TOKEN_ACCOUNT_LEN)
    throw new Error(`the USDC account ${address.toBase58()} has an unexpected size`);
  let token;
  try {
    token = decodeTokenAccount(acct.data);
  } catch (err) {
    throw new Error(`the USDC account ${address.toBase58()} cannot be decoded: ${describeError(err)}`);
  }
  if (!token.mint.equals(mint))
    throw new Error(`the USDC account ${address.toBase58()} holds another mint`);
  if (!token.owner.equals(recipient))
    throw new Error(`the USDC account ${address.toBase58()} was reassigned; the recipient cannot spend it`);
  if (token.state !== "initialized")
    throw new Error(`the USDC account ${address.toBase58()} is ${token.state}`);
}

/** A wallet that can't sign: enough for Anchor to build instructions and simulate. */
function readonlyWallet(publicKey: PublicKey) {
  const refuse = async (): Promise<never> => {
    throw new Error("GuardClient holds no keys; pass a Keypair to the call that needs one");
  };
  return { publicKey, signTransaction: refuse, signAllTransactions: refuse } as any;
}

export class GuardClient {
  readonly program: Program<AegisGuard>;
  readonly pdas: GuardPdas;
  readonly reader: AccountReader;

  /**
   * @param viewer a funded System account used as the fee payer when simulating
   *   `assess`. A simulation needs one, but no signature.
   */
  constructor(
    readonly connection: Connection,
    readonly programId: PublicKey = new PublicKey(idl.address),
    readonly viewer: PublicKey | null = null
  ) {
    const provider = new AnchorProvider(connection, readonlyWallet(viewer ?? PublicKey.default), {
      commitment: "confirmed",
      preflightCommitment: "confirmed",
    });
    this.program = new Program<AegisGuard>({ ...(idl as AegisGuard), address: programId.toBase58() }, provider);
    this.pdas = new GuardPdas(programId);
    this.reader = connectionReader(connection);
  }

  async config(): Promise<ConfigData | null> {
    const [acct] = await this.reader.getAccounts([this.pdas.config]);
    return readConfig(acct, this.programId);
  }

  /** Reads the exact entry PDA. Throws on an RPC error: "unknown" is not "absent". */
  async entry(kind: EntryKind, key: PublicKey): Promise<{ member: boolean; controller: PublicKey | null }> {
    const [acct] = await this.reader.getAccounts([this.pdas.entry(kind, key)]);
    const e = readEntry(acct, this.programId);
    return { member: e !== null, controller: e?.controller ?? null };
  }

  /** The accounts `guarded_pay` and `assess` judge, derived the way the program derives them. */
  async policyAccounts(recipient: PublicKey, destination?: PublicKey) {
    const mint = (await this.config())?.mint ?? USDC_MINT;
    const dest = destination ?? associatedTokenAddress(recipient, mint);
    const allowEntry = this.pdas.entry("allow", recipient);
    const [recipientAcct, allowAcct] = await this.reader.getAccounts([recipient, allowEntry]);
    const owner = recipientAcct?.owner ?? SYSTEM_PROGRAM;
    const allow = readEntry(allowAcct, this.programId);
    return {
      recipient,
      destination: dest,
      denyEntry: this.pdas.entry("deny", recipient),
      allowEntry,
      blockprogOwner: this.pdas.entry("blockprog", owner),
      blockprogController: allow?.controller ? this.pdas.entry("blockprog", allow.controller) : null,
    };
  }

  /** The program's own verdict for this payment, by simulation. No transaction is sent. */
  async assess(recipient: PublicKey, amountUnits: bigint, opts: { destination?: PublicKey } = {}): Promise<OnchainAssessment> {
    if (!this.viewer) throw new Error("assess needs a funded viewer address to simulate with");
    const a = await this.program.methods
      .assess(new BN(amountUnits.toString()))
      .accountsPartial({ config: this.pdas.config, ...(await this.policyAccounts(recipient, opts.destination)) })
      .view();
    const verdict = ({ pay: "PAY", review: "REVIEW", block: "BLOCK" } as const)[Object.keys(a.verdict)[0] as "pay" | "review" | "block"];
    const reason = Object.keys(a.reason)[0];
    return {
      verdict,
      reason,
      code: guardReasonCode(reason),
      spentToday: BigInt(a.spentToday.toString()),
      dailyLimit: BigInt(a.dailyLimit.toString()),
    };
  }

  async guardedPayInstruction(agent: PublicKey, recipient: PublicKey, amountUnits: bigint, destination?: PublicKey): Promise<TransactionInstruction> {
    const cfg = await this.config();
    if (!cfg) throw new Error(`aegis_guard at ${this.programId.toBase58()} is not initialized`);
    return this.program.methods
      .guardedPay(new BN(amountUnits.toString()))
      .accountsPartial({
        agent,
        agentEntry: this.pdas.entry("agent", agent),
        config: this.pdas.config,
        vault: cfg.vault,
        mint: cfg.mint,
        stats: this.pdas.stats(recipient),
        ...(await this.policyAccounts(recipient, destination)),
      })
      .instruction();
  }

  /**
   * Pays through the guard, signed by the agent. With `skipPreflight` a refused
   * payment still lands on-chain as a failed transaction (the drain demo); the
   * outcome says so and carries the refusal code either way.
   */
  async guardedPay(
    agent: Keypair,
    recipient: PublicKey,
    amountUnits: bigint,
    opts: { destination?: PublicKey; skipPreflight?: boolean } = {}
  ): Promise<SendOutcome> {
    let ix: TransactionInstruction;
    try {
      ix = await this.guardedPayInstruction(agent.publicKey, recipient, amountUnits, opts.destination);
    } catch (err: any) {
      return { ok: false, signature: null, landed: false, code: null, error: describeError(err), logs: [] };
    }
    return this.send([ix], [agent], opts.skipPreflight ?? false);
  }

  async addEntry(owner: Keypair, kind: EntryKind, key: PublicKey, controller: PublicKey | null = null): Promise<SendOutcome> {
    const ix = await this.program.methods
      .addEntry(KIND_ARG[kind] as any, key, controller ?? PublicKey.default)
      .accountsPartial({ owner: owner.publicKey, config: this.pdas.config, entry: this.pdas.entry(kind, key) })
      .instruction();
    return this.send([ix], [owner], false);
  }

  async removeEntry(owner: Keypair, kind: EntryKind, key: PublicKey): Promise<SendOutcome> {
    const ix = await this.program.methods
      .removeEntry(KIND_ARG[kind] as any, key)
      .accountsPartial({ owner: owner.publicKey, config: this.pdas.config, entry: this.pdas.entry(kind, key) })
      .instruction();
    return this.send([ix], [owner], false);
  }

  /**
   * Writes one refusal receipt (`log_refusal`), signed by a reporter. It touches
   * no vault account. `code` must be an uppercase refusal code (at most 32
   * bytes) and `reason` 1 to 256 bytes; the program checks both.
   */
  async logRefusal(
    reporter: Keypair,
    entry: { recipient: PublicKey | null; amount: bigint; verdict: "BLOCK" | "ASK_HUMAN"; code: string; reason: string }
  ): Promise<SendOutcome> {
    let ix: TransactionInstruction;
    try {
      ix = await this.program.methods
        .logRefusal(entry.recipient, new BN(entry.amount.toString()), entry.verdict === "ASK_HUMAN" ? { askHuman: {} } : { block: {} }, entry.code, entry.reason)
        .accountsPartial({ reporter: reporter.publicKey, reporterEntry: this.pdas.entry("reporter", reporter.publicKey), config: this.pdas.config, audit: this.pdas.audit })
        .instruction();
    } catch (err) {
      return { ok: false, signature: null, landed: false, code: null, error: describeError(err), logs: [] };
    }
    return this.send([ix], [reporter], false);
  }

  /** The audit log's own counter: how many receipts were ever written. null when it can't be read as one. */
  async refusalCount(): Promise<bigint | null> {
    const [acct] = await this.reader.getAccounts([this.pdas.audit]);
    if (!acct || !acct.owner.equals(this.programId) || acct.data.length < 17 || !acct.data.subarray(0, 8).equals(accountDiscriminator("AuditLog"))) return null;
    return acct.data.readBigUInt64LE(8);
  }

  /** Decodes this program's self-CPI events (`emit_cpi!`) from a landed transaction. */
  async events(signature: string): Promise<{ name: string; data: any }[]> {
    const tx = await this.connection.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    if (!tx?.meta) return [];
    const keys = tx.transaction.message.getAccountKeys({ accountKeysFromLookups: tx.meta.loadedAddresses });
    const out: { name: string; data: any }[] = [];
    for (const inner of tx.meta.innerInstructions ?? []) {
      for (const ix of inner.instructions) {
        if (!keys.get(ix.programIdIndex)?.equals(this.programId)) continue;
        const data = Buffer.from(utils.bytes.bs58.decode(ix.data));
        if (!data.subarray(0, 8).equals(EVENT_IX_TAG)) continue;
        const ev = this.program.coder.events.decode(data.subarray(8).toString("base64"));
        if (ev) out.push(ev);
      }
    }
    return out;
  }

  /**
   * Creates the recipient's USDC account, paid by `payer` (decision 8). Only for
   * a wallet on the curve: an ATA for a PDA or a program-owned address is a
   * vetting question, not a convenience, so this refuses those.
   *
   * Lamports alone at the ATA address (anyone can send them) don't count as an
   * account: CreateIdempotent handles a pre-funded address, so it is sent.
   */
  async ensureRecipientAta(payer: Keypair, recipient: PublicKey): Promise<{ address: PublicKey; created: boolean; outcome: SendOutcome | null }> {
    const mint = (await this.config())?.mint ?? USDC_MINT;
    const address = associatedTokenAddress(recipient, mint);
    const [recipientAcct, ataAcct] = await this.reader.getAccounts([recipient, address]);
    if (ataAcct?.owner.equals(TOKEN_PROGRAM)) {
      checkRecipientAta(ataAcct, address, recipient, mint);
      return { address, created: false, outcome: null };
    }
    if (ataAcct && !(ataAcct.owner.equals(SYSTEM_PROGRAM) && ataAcct.data.length === 0)) {
      throw new Error(`the USDC account address ${address.toBase58()} holds an account owned by ${ataAcct.owner.toBase58()}; it can't be created there`);
    }
    const systemOwned = !recipientAcct || recipientAcct.owner.equals(SYSTEM_PROGRAM);
    if (!PublicKey.isOnCurve(recipient.toBytes()) || !systemOwned) {
      throw new Error("refusing to create a USDC account for a program-controlled recipient; vet it first");
    }
    const ix = new TransactionInstruction({
      programId: ATA_PROGRAM,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: address, isSigner: false, isWritable: true },
        { pubkey: recipient, isSigner: false, isWritable: false },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: TOKEN_PROGRAM, isSigner: false, isWritable: false },
      ],
      data: Buffer.from([1]), // CreateIdempotent
    });
    const outcome = await this.send([ix], [payer], false);
    if (outcome.ok) return { address, created: true, outcome };
    // Whatever the send reported, the account is the truth.
    if (outcome.landed !== false) {
      const [after] = await this.reader.getAccounts([address]);
      if (after?.owner.equals(TOKEN_PROGRAM)) {
        checkRecipientAta(after, address, recipient, mint);
        return { address, created: true, outcome };
      }
    }
    throw new Error(`could not create the USDC account: ${outcome.error}`);
  }

  /**
   * Sends and follows the transaction until its fate is known. Never throws.
   *
   * The signature is taken from the signed transaction before sending, so a
   * transport error after submission can still be followed up. Confirmation is
   * by polling the signature's status (no websocket), and that status is the
   * authority on success: the transaction fetch afterwards is only for logs.
   *   landed true:  on-chain, fee paid; `ok` says whether it succeeded.
   *   landed false: rejected before reaching the chain, or its blockhash expired unseen.
   *   landed null:  could not tell in time. Check `signature` before retrying.
   */
  async send(ixs: TransactionInstruction[], signers: Keypair[], skipPreflight: boolean): Promise<SendOutcome> {
    let signature: string | null = null;
    let lastValidBlockHeight: number;
    let raw: Buffer;
    try {
      const latest = await this.connection.getLatestBlockhash("confirmed");
      lastValidBlockHeight = latest.lastValidBlockHeight;
      const tx = new Transaction({ feePayer: signers[0].publicKey, blockhash: latest.blockhash, lastValidBlockHeight }).add(...ixs);
      tx.sign(...signers);
      signature = utils.bytes.bs58.encode(tx.signature!);
      raw = tx.serialize();
    } catch (err) {
      return this.failed(err, signature, false);
    }
    let sendError: unknown = null;
    try {
      await this.connection.sendRawTransaction(raw, { skipPreflight, preflightCommitment: "confirmed" });
    } catch (err) {
      // The RPC answered with an error (a preflight refusal, a bad blockhash):
      // the transaction was not forwarded. Anything else (a dropped connection)
      // may have happened after it was, so its status is followed below.
      if (err instanceof SendTransactionError) return this.failed(err, signature, false);
      sendError = err;
    }
    return this.settle(signature, lastValidBlockHeight, sendError);
  }

  /** How long `send` follows a transaction, and how often it polls. */
  sendTimeoutMs = 90_000;
  pollMs = 400;

  private async settle(signature: string, lastValidBlockHeight: number, sendError: unknown): Promise<SendOutcome> {
    const followed = await followSignature(this.connection, signature, blockHeightExpiry(this.connection, lastValidBlockHeight), {
      timeoutMs: this.sendTimeoutMs,
      pollMs: this.pollMs,
      sendError,
    });
    if (followed.outcome === "confirmed") return this.landedOutcome(signature, followed.err);
    return { ok: false, signature, landed: followed.outcome === "expired" ? false : null, code: null, error: followed.why, logs: [] };
  }

  private async landedOutcome(signature: string, err: unknown): Promise<SendOutcome> {
    const logs = await fetchLogs(this.connection, signature, this.pollMs);
    if (err === null) return { ok: true, signature, landed: true, code: null, error: null, logs: logs ?? [] };
    return {
      ok: false,
      signature,
      landed: true,
      code: guardFailureCode(this.programId.toBase58(), null, logs ?? []),
      error: `transaction failed on-chain: ${JSON.stringify(err)}${logs ? "" : " (its logs could not be fetched)"}`,
      logs: logs ?? [],
    };
  }

  private failed(err: any, signature: string | null, landed: boolean): SendOutcome {
    const logs: string[] = [...(err?.logs ?? []), ...(err?.transactionLogs ?? [])];
    return {
      ok: false,
      signature,
      landed,
      code: guardFailureCode(this.programId.toBase58(), err, logs),
      error: describeError(err),
      logs: [...new Set(logs)],
    };
  }
}

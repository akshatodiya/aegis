// The x402 rail's receipt drawer: refusals written to aegis_guard's audit log.
//
// On the treasury rail a refusal is already public: guarded_pay fails and the
// failed transaction stays on-chain. On the x402 rail there is nothing to look
// at, because the payment was a signature we declined to make. This module
// gives that absence a receipt (`log_refusal`, a self-CPI `Refused` event).
//
// Three rules, in order of how easy they are to get wrong:
//  1. Logging never sits in the refusal path. onRefuse() is synchronous, never
//     throws, and returns at once; the write happens behind it. The refusal
//     already happened, and bookkeeping must not delay or break it.
//  2. One refusal, one entry. The same error object surfaces through both x402
//     hooks (the signer refuses, the fetch wrapper re-throws), so entries are
//     deduped on object identity. Not text: two separate refusals that read
//     the same are two entries.
//  3. One write at a time. They come from one reporter key, and each id is the
//     counter + 1, so writes queue rather than race for it.
//
// Each receipt costs the reporter a transaction fee, and the counterparty
// chooses how many refusals there are. So a run writes at most `maxWrites`
// receipts; refusals past that still happen and still print, and flush() says
// how many went unrecorded. It is not an enforcement point: by the time it
// runs, the signature was already never made. An empty log proves nothing, and
// a reporter key can write anything it likes.
import { Keypair, PublicKey } from "@solana/web3.js";

import { GuardClient } from "./guard/client";
import { REFUSAL, isRefusalCode } from "./refusals";
import type { AegisPaymentRefused } from "./x402/refused";

/** The program's own limit (MAX_REASON_LEN); over it the write fails, so trim first. */
export const MAX_REASON_BYTES = 256;
const U64_MAX = (1n << 64n) - 1n;

/**
 * Fits a reason into what the program accepts, measured as it measures: in
 * UTF-8 bytes. Reasons quote the wire (a demanded amount is any digit string a
 * 402 sends), so trimming is what stops a merchant deciding how big our
 * receipt transaction is.
 */
export function trimReason(reason: unknown): string {
  const text = String(reason ?? "").replace(/\s+/g, " ").trim();
  if (text === "") return "refused (no reason recorded)";
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= MAX_REASON_BYTES) return text;
  // Cut short of the limit, drop a character the cut split, and say it was cut.
  const head = bytes.subarray(0, MAX_REASON_BYTES - 3).toString("utf8").replace(/�+$/, "");
  return `${head}...`;
}

export interface AuditEntry {
  recipient: PublicKey | null;
  amount: bigint;
  verdict: "BLOCK" | "ASK_HUMAN";
  /** Its own field on-chain, so a long reason can't push it out. */
  code: string;
  reason: string;
  signature?: string;
  error?: string;
  skipped?: boolean;
}

/** The fields the program stores, from a refusal. Tolerant of anything: this runs on the failure path. */
export function refusalEntry(err: Partial<AegisPaymentRefused> | null | undefined): AuditEntry {
  let recipient: PublicKey | null = null;
  try {
    if (typeof err?.recipient === "string") {
      const k = new PublicKey(err.recipient);
      recipient = k.toBase58() === err.recipient ? k : null;
    }
  } catch {
    recipient = null;
  }
  // A 402 can demand a number no u64 holds; recording a clamped one would be a
  // quieter lie than recording none. The reason still says what was asked.
  let amount = 0n;
  try {
    const raw = BigInt((err?.amount as bigint | null | undefined) ?? 0);
    if (raw >= 0n && raw <= U64_MAX) amount = raw;
  } catch {
    amount = 0n;
  }
  return {
    recipient,
    amount,
    verdict: err?.verdict === "ASK_HUMAN" ? "ASK_HUMAN" : "BLOCK",
    code: isRefusalCode(err?.code) ? err!.code! : REFUSAL.UNKNOWN,
    reason: trimReason(err?.reason ?? err?.message),
  };
}

export type AuditSend = (entry: AuditEntry) => Promise<string>;

export interface AuditLogger {
  enabled: boolean;
  onRefuse: (err: AegisPaymentRefused) => void;
  flush(): Promise<{ entries: AuditEntry[]; logged: number; failed: number; skipped: number }>;
  entries: AuditEntry[];
}

/**
 * The onRefuse hook both x402 hooks are handed. Writes with `client` signed by
 * `reporter` (a key in the guard's reporter list, holding SOL for fees), or with
 * an injected `send` in tests. With neither, it is disabled and onRefuse is a
 * no-op, so every rail still runs without receipts.
 */
export function createAuditLogger(opts: { client?: GuardClient; reporter?: Keypair; send?: AuditSend; log?: (msg: string) => void; maxWrites?: number } = {}): AuditLogger {
  const { client, reporter, log = () => {}, maxWrites = 25 } = opts;
  const send: AuditSend | null =
    opts.send ??
    (client && reporter
      ? async (entry) => {
          const out = await client.logRefusal(reporter, entry);
          if (out.ok && out.signature) return out.signature;
          if (out.landed === null) throw new Error(`could not tell whether the receipt landed (${out.signature}): ${out.error}`);
          throw new Error(out.error ?? "the receipt was not written");
        }
      : null);
  const enabled = send !== null;
  const entries: AuditEntry[] = [];
  const seen = new WeakSet<object>();
  let queue: Promise<void> = Promise.resolve();
  let written = 0;
  let capNoted = false;

  function say(message: string) {
    try {
      log(message);
    } catch {
      // Printing must not change whether a receipt was written.
    }
  }

  function onRefuse(err: AegisPaymentRefused) {
    try {
      if (!enabled || !err || typeof err !== "object") return;
      if (seen.has(err)) return; // rule 2
      seen.add(err);
      const entry = refusalEntry(err);
      entries.push(entry);
      if (written >= maxWrites) {
        entry.skipped = true;
        if (!capNoted) {
          capNoted = true;
          say(`${maxWrites} receipts written this run: refusals continue, receipts stop (each one costs the reporter a fee).`);
        }
        return;
      }
      written += 1;
      // rules 1 and 3: queue the write and return. The catch is attached here,
      // so a failed write can never surface as an unhandled rejection.
      queue = queue.then(async () => {
        try {
          entry.signature = await send!(entry);
          say(`refusal receipt written on-chain: ${entry.signature}`);
        } catch (writeErr: any) {
          entry.error = writeErr?.message ?? String(writeErr);
          say(`could not write the refusal receipt: ${entry.error}`);
        }
      });
    } catch {
      // rule 1: never throw into the refusal path
    }
  }

  async function flush() {
    await queue;
    return {
      entries,
      logged: entries.filter((e) => e.signature).length,
      failed: entries.filter((e) => e.error).length,
      skipped: entries.filter((e) => e.skipped).length,
    };
  }

  return { enabled, onRefuse, flush, entries };
}

export interface ReadEntry {
  id: bigint;
  reporter: string;
  recipient: string | null;
  amount: bigint;
  verdict: "BLOCK" | "ASK_HUMAN";
  code: string;
  reason: string;
  timestamp: number;
  signature: string;
}

/**
 * Reads receipts back from the audit account's transaction history, newest
 * first, plus the program's own counter. `complete` is whether the two agree:
 * history is bounded by `limit` and by what the RPC retains, so it is the only
 * way to tell a short log from a short answer.
 */
export async function readRefusals(client: GuardClient, { limit = 1000 }: { limit?: number } = {}): Promise<{ entries: ReadEntry[]; total: bigint | null; complete: boolean }> {
  const total = await client.refusalCount();
  const entries: ReadEntry[] = [];
  let before: string | undefined;
  let fetched = 0;
  while (fetched < limit) {
    const page = await client.connection.getSignaturesForAddress(client.pdas.audit, { before, limit: Math.min(1000, limit - fetched) }, "confirmed");
    if (page.length === 0) break;
    fetched += page.length;
    before = page[page.length - 1].signature;
    for (const s of page) {
      if (s.err) continue;
      for (const ev of await client.events(s.signature)) {
        if (ev.name !== "refused" && ev.name !== "Refused") continue;
        const d = ev.data;
        entries.push({
          id: BigInt(d.id.toString()),
          reporter: d.reporter.toBase58(),
          recipient: d.recipient ? d.recipient.toBase58() : null,
          amount: BigInt(d.amount.toString()),
          verdict: "askHuman" in d.verdict ? "ASK_HUMAN" : "BLOCK",
          code: d.code,
          reason: d.reason,
          timestamp: Number(d.timestamp.toString()),
          signature: s.signature,
        });
      }
    }
  }
  return { entries, total, complete: total !== null && BigInt(entries.length) === total };
}

// Following a sent transaction to a known end. Shared by the guard client and
// the x402 merchant, because both must answer the same question honestly:
// did it land, did it succeed, or can't we tell?
//
// Confirmation is by polling the signature's status (no websocket), and that
// status is the authority on success. Expiry is when the transaction's
// blockhash can no longer be used: after that, a signature that was never seen
// never will be.
import { Connection } from "@solana/web3.js";

export type TxStatus = { seen: "confirmed"; err: unknown } | { seen: "pending" | "never" | "unknown" };

/** true: expired, so an unseen transaction can't land any more. false: not yet. null: couldn't tell. */
export type Expiry = () => Promise<boolean | null>;

export function blockHeightExpiry(connection: Connection, lastValidBlockHeight: number): Expiry {
  return async () => {
    const height = await connection.getBlockHeight("confirmed").catch(() => null);
    return height === null ? null : height > lastValidBlockHeight;
  };
}

/** For a transaction someone else built: only its blockhash is known. */
export function blockhashExpiry(connection: Connection, blockhash: string): Expiry {
  return async () => {
    try {
      const { value } = await connection.isBlockhashValid(blockhash, { commitment: "confirmed" });
      return !value;
    } catch {
      return null;
    }
  };
}

export async function signatureStatus(connection: Connection, signature: string): Promise<TxStatus> {
  const { value } = await connection.getSignatureStatuses([signature], { searchTransactionHistory: true });
  const s = value?.[0];
  if (!s) return { seen: "never" };
  if (s.confirmationStatus !== "confirmed" && s.confirmationStatus !== "finalized") return { seen: "pending" };
  return { seen: "confirmed", err: s.err ?? null };
}

export type Followed =
  | { outcome: "confirmed"; err: unknown }
  | { outcome: "expired"; why: string }
  | { outcome: "unknown"; why: string };

export interface FollowOptions {
  timeoutMs: number;
  pollMs: number;
  /** An error from the send itself, if it threw after the transaction may have left. */
  sendError?: unknown;
}

export async function followSignature(connection: Connection, signature: string, expired: Expiry, opts: FollowOptions): Promise<Followed> {
  const deadline = Date.now() + opts.timeoutMs;
  let lastError: unknown = opts.sendError ?? null;
  const look = () =>
    signatureStatus(connection, signature).catch((err): TxStatus => {
      lastError = err;
      return { seen: "unknown" };
    });
  for (;;) {
    let s = await look();
    if (s.seen === "confirmed") return { outcome: "confirmed", err: s.err };
    if ((await expired()) === true) {
      // Expired. One last look, in case it landed just before.
      s = await look();
      if (s.seen === "confirmed") return { outcome: "confirmed", err: s.err };
      if (s.seen === "never") {
        const why = opts.sendError
          ? `the send failed (${describeError(opts.sendError)}) and the blockhash expired without the transaction landing`
          : "the blockhash expired without the transaction landing";
        return { outcome: "expired", why };
      }
    }
    if (Date.now() > deadline) {
      return { outcome: "unknown", why: `could not tell whether ${signature} landed${lastError ? ` (${describeError(lastError)})` : ""}; check it before retrying` };
    }
    await new Promise((r) => setTimeout(r, opts.pollMs));
  }
}

/** Best effort: null when the transaction can't be fetched. Never decides success. */
export async function fetchLogs(connection: Connection, signature: string, pollMs: number, tries = 10): Promise<string[] | null> {
  for (let i = 0; i < tries; i++) {
    try {
      const tx = await connection.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      if (tx?.meta) return tx.meta.logMessages ?? [];
    } catch {
      // fall through and retry
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return null;
}

export function describeError(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (typeof err === "string") return err;
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

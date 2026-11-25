// Behavior lane: a spend-size check against the guard's own payment history.
//
// On EVM this scanned a 50k-block window of Paid logs. Here guarded_pay keeps a
// small stats account per recipient ({count, largest, total}), so one read gives
// every payment this guard has made to them. Two limits of that history: it is
// all-time, so the 5x anchor below never decays; and it covers guarded_pay only,
// since x402 payments never pass the guard.
//
// Three answers stay three answers: never paid (no stats account), paid before
// (the numbers), and could not tell (an RPC or layout error, reported as such and
// never phrased as "never").
//
// The size half is not decoration: a count alone can be bought with one dust
// payment, so familiarity is capped at a multiple of what we actually paid them.
import { PublicKey } from "@solana/web3.js";

import { AccountReader } from "../chain/reader";
import { GuardPdas, readStats } from "../guard/layout";
import { formatUnits } from "../units";

// Base units throughout, so "exactly 5x" is exact (50_000_000n = 50 USDC).
const AMOUNT_THRESHOLD = 50_000_000n;
// how far past the largest payment we've made to someone counts as new territory
const TRUST_MULTIPLE = 5n;

export interface PaidHistory {
  count: number;
  /** Largest single payment, in base units. */
  largest: bigint;
}

export interface BehaviorResult {
  lane: "behavior";
  level: "LOW" | "MEDIUM";
  escalate: boolean;
  reason: string;
  /** null = unknown (could not be read, or no guard configured), never "never paid". */
  history: PaidHistory | null;
}

/** The guard's history with this recipient. null = could not be read (or no guard configured). */
export async function timesPaid(reader: AccountReader, guard: PublicKey | null | undefined, recipient: PublicKey): Promise<PaidHistory | null> {
  if (!guard) return null;
  try {
    const pdas = new GuardPdas(guard);
    const [acct] = await reader.getAccounts([pdas.stats(recipient)]);
    const stats = readStats(acct, guard);
    if (!stats) return { count: 0, largest: 0n };
    return { count: Number(stats.count), largest: stats.largest };
  } catch {
    return null; // rate limited, RPC down, or a layout we don't recognize: don't guess
  }
}

/**
 * The pure decision, in base units. `paid` is null when the history is unknown;
 * `unknownWhy` says why, in words.
 */
export function behaviorVerdict(units: bigint, paid: PaidHistory | null, unknownWhy = "could not be read"): BehaviorResult {
  const amount = formatUnits(units);
  const threshold = formatUnits(AMOUNT_THRESHOLD);
  const large = units > AMOUNT_THRESHOLD;
  const unknown = paid === null;
  const count = unknown ? 0 : paid.count;
  const largest = unknown ? 0n : paid.largest;
  const beyondHistory = units > largest * TRUST_MULTIPLE;

  if (large && (unknown || count === 0 || beyondHistory)) {
    let reason;
    if (unknown) {
      reason = `Large payment (${amount} USDC > ${threshold}) and the guard's payment history ${unknownWhy} - worth a human glance.`;
    } else if (count === 0) {
      reason = `Large payment (${amount} USDC > ${threshold}) to a recipient the guard has not paid before - worth a human glance.`;
    } else {
      reason = `Large payment (${amount} USDC > ${threshold}), and over ${TRUST_MULTIPLE}x the largest the guard has paid this recipient before (${formatUnits(largest)} USDC across ${count} payment${count === 1 ? "" : "s"}) - worth a human glance.`;
    }
    return { lane: "behavior", level: "MEDIUM", escalate: true, reason, history: paid };
  }

  const seen = unknown
    ? "history unavailable"
    : count === 0
      ? "no prior payments through the guard"
      : `paid ${count} time${count === 1 ? "" : "s"} before, up to ${formatUnits(largest)} USDC`;
  return {
    lane: "behavior",
    level: "LOW",
    escalate: false,
    reason: `Amount ${amount} USDC within normal range for this recipient (${seen}).`,
    history: paid,
  };
}

export async function checkBehavior(reader: AccountReader, guard: PublicKey | null | undefined, recipient: PublicKey, units: bigint): Promise<BehaviorResult> {
  return behaviorVerdict(units, await timesPaid(reader, guard, recipient), guard ? "could not be read" : "was not consulted (no guard configured)");
}

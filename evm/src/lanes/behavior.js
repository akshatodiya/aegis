// behavior lane - a spend-size check, now with a real payment history behind it.
//
// this used to keep a hardcoded empty `KNOWN` set that nothing ever wrote to, so
// "first-time recipient" was true for every address forever and the rule was
// really just "is this a large payment" wearing a costume. rather than invent a
// history, we read the one the system already produces: AegisGuard emits
// Paid(agent, to, amount) on every guarded transfer, and `to` is indexed, so the
// guard's own logs are an honest record of who we have actually paid before.
//
// no database, no external feed, no scores. just the chain telling us whether we
// have seen this recipient, and for how much. if the log query fails (rate limit,
// no guard wired up yet) we say the history is UNKNOWN rather than pretending
// it's empty - "we have never paid them" and "we can't tell" are different claims.
//
// the size half is not decoration. a lane that only counts payments trusts a
// number the attacker can move: one dust payment through the small-amount path
// buys a permanent "known recipient" pass at any size. so familiarity is capped
// at a multiple of what we have actually paid them before.
import { parseAbiItem } from 'viem';
import { publicClient, addresses } from '../config.js';

// plain USDC numbers, not base units (50 = 50 USDC)
const AMOUNT_THRESHOLD = 50;

// how far past the biggest payment we've already made to someone counts as new
// territory. "we've paid them before" is only worth something up to the size we
// actually trusted them with, so this is the ratio that turns a familiar
// recipient back into an unfamiliar one.
const TRUST_MULTIPLE = 5;

const PAID = parseAbiItem('event Paid(address indexed agent, address indexed to, uint256 amount)');

// how far back to look. the public Arc gateways reject wide getLogs ranges
// (~100k blocks is where they start failing), so this is a window, not the whole
// chain, and the wording below says so rather than claiming "never". covering
// full history properly needs an indexer, which is a real answer for a real
// deployment and out of scope here - what we won't do is imply we have one.
const WINDOW = 50_000n;

// what the guard's own logs say about this recipient inside the window: how many
// times we've paid them, and the largest single payment we've made. null means we
// could not find out, which is deliberately distinct from "never paid".
//
// the size matters as much as the count. a count on its own is the cheap half of
// the signal, because an attacker can manufacture it (see behaviorVerdict), and
// the amount is right there in the event we're already reading.
export async function timesPaid(recipient) {
  if (!addresses.guard) return null;
  try {
    const latest = await publicClient.getBlockNumber();
    const logs = await publicClient.getLogs({
      address: addresses.guard,
      event: PAID,
      args: { to: recipient },
      fromBlock: latest > WINDOW ? latest - WINDOW : 0n,
      toBlock: 'latest',
    });
    // Paid carries the same base-units amount guardedPay moved through the
    // 6-decimal ERC-20, and this lane thinks in whole USDC, so convert here at
    // the edge rather than leaving two units loose in the same function.
    let largestBase = 0n;
    for (const log of logs) {
      const value = log.args?.amount ?? 0n;
      if (value > largestBase) largestBase = value;
    }
    return { count: logs.length, largest: Number(largestBase) / 1e6 };
  } catch {
    return null; // rate limited or range rejected - don't guess
  }
}

// the pure decision, so the branch logic is testable without a chain.
// `paid` is { count, largest } in whole USDC, or null when the history could not
// be read.
export function behaviorVerdict(amount, paid) {
  const large = amount > AMOUNT_THRESHOLD;
  const unknown = paid === null;
  const count = unknown ? 0 : paid.count;
  const largest = unknown ? 0 : paid.largest;

  // this used to ask only whether the count was zero, and that's a signal an
  // attacker can manufacture for about a dollar: get one dust payment through -
  // which passes precisely because it's small - and every later payment to that
  // address reads as "known recipient" forever, at any size. the count is the
  // cheap half. so a recipient is only familiar up to a multiple of what we have
  // actually trusted them with, and past that they're a stranger again.
  const beyondHistory = amount > largest * TRUST_MULTIPLE;

  if (large && (unknown || count === 0 || beyondHistory)) {
    let reason;
    if (unknown) {
      reason = `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}) and the guard's payment history could not be read - worth a human glance.`;
    } else if (count === 0) {
      reason = `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}) to a recipient the guard has not paid in its recent history - worth a human glance.`;
    } else {
      reason = `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}), and over ${TRUST_MULTIPLE}x the largest the guard has paid this recipient before (${largest} USDC across ${count} payment${count === 1 ? '' : 's'}) - worth a human glance.`;
    }
    return { lane: 'behavior', level: 'MEDIUM', escalate: true, reason };
  }

  const seen = unknown
    ? 'history unavailable'
    : count === 0
      ? 'no prior payments in recent history'
      : `paid ${count} time${count === 1 ? '' : 's'} before, up to ${largest} USDC`;
  return {
    lane: 'behavior',
    level: 'LOW',
    escalate: false,
    reason: `Amount ${amount} USDC within normal range for this recipient (${seen}).`,
  };
}

export async function checkBehavior(recipient, amount) {
  return behaviorVerdict(amount, await timesPaid(recipient));
}

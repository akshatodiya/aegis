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
// have seen this recipient. if the log query fails (rate limit, no guard wired
// up yet) we say the history is UNKNOWN rather than pretending it is empty -
// "we have never paid them" and "we cannot tell" are different claims.
import { parseAbiItem } from 'viem';
import { publicClient, addresses } from '../config.js';

// plain USDC numbers, not base units (50 = 50 USDC)
const AMOUNT_THRESHOLD = 50;

const PAID = parseAbiItem('event Paid(address indexed agent, address indexed to, uint256 amount)');

// how far back to look. the public Arc gateways reject wide getLogs ranges
// (~100k blocks is where they start failing), so this is a window, not the whole
// chain, and the wording below says so rather than claiming "never". covering
// full history properly needs an indexer, which is a real answer for a real
// deployment and out of scope here - what we will not do is imply we have one.
const WINDOW = 50_000n;

// how many times the guard has paid this recipient inside the window. null means
// we could not find out, which is deliberately distinct from 0.
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
    return logs.length;
  } catch {
    return null; // rate limited or range rejected - don't guess
  }
}

// the pure decision, so the branch logic is testable without a chain.
// `paid` is a count, or null when the history could not be read.
export function behaviorVerdict(amount, paid) {
  const large = amount > AMOUNT_THRESHOLD;
  const unknown = paid === null;
  const firstTime = paid === 0;

  if (large && (firstTime || unknown)) {
    return {
      lane: 'behavior',
      level: 'MEDIUM',
      escalate: true,
      reason: unknown
        ? `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}) and the guard's payment history could not be read - worth a human glance.`
        : `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}) to a recipient the guard has not paid in its recent history - worth a human glance.`,
    };
  }

  const seen = unknown
    ? 'history unavailable'
    : paid === 0
      ? 'no prior payments in recent history'
      : `paid ${paid} time${paid === 1 ? '' : 's'} before`;
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

// behavior lane - mock for now.
// real version would model spend velocity / anomalies. here it's just an
// amount threshold + a first-time-recipient nudge toward ASK_HUMAN.

// plain USDC numbers, not base units (50 = 50 USDC)
const AMOUNT_THRESHOLD = 50;

// addresses we've "seen before". be honest about what this is: nothing ever
// writes to it, so `firstTime` below is true for every recipient and the rule
// collapses to "is this a large payment". it's the seam a real payment history
// would plug into, not a signal we actually have today.
const KNOWN = new Set([]);

export function checkBehavior(recipient, amount) {
  const firstTime = !KNOWN.has(recipient.toLowerCase());
  const large = amount > AMOUNT_THRESHOLD;

  if (large && firstTime) {
    return {
      lane: 'behavior',
      level: 'MEDIUM',
      escalate: true,
      reason: `Large payment (${amount} USDC > ${AMOUNT_THRESHOLD}) and no payment history to weigh it against - worth a human glance.`,
    };
  }
  return {
    lane: 'behavior',
    level: 'LOW',
    escalate: false,
    reason: `Amount ${amount} USDC within normal range for this recipient.`,
  };
}

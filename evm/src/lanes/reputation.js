// reputation lane. mock for now.
// TODO: wire this to a real feed - x402 payment history + shared denylists.
// for the demo it's just two lookup maps, both empty in v1.

const DENYLIST = new Map([
  // 0xabc...(lowercase) -> reason
]);

const ALLOWLIST = new Map([
]);

export function checkReputation(recipient) {
  const key = recipient.toLowerCase();

  if (DENYLIST.has(key)) {
    return {
      lane: 'reputation',
      level: 'HIGH',
      listed: 'deny',
      reason: `On denylist: ${DENYLIST.get(key)}`,
    };
  }
  if (ALLOWLIST.has(key)) {
    return {
      lane: 'reputation',
      level: 'LOW',
      listed: 'allow',
      reason: `On allowlist: ${ALLOWLIST.get(key)}`,
    };
  }
  return {
    lane: 'reputation',
    level: 'LOW',
    listed: null,
    reason: 'No reputation record (mock lane - allow/deny lists are empty in V1).',
  };
}

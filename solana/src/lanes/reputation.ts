// Reputation lane. Still a mock, as on EVM: two lookup maps, empty in v1. What
// is real is the guard's own deny list, which the inspection lane reads and
// passes in, so an address the owner denylisted on-chain is refused off-chain
// too (including on the x402 rail, which never reaches the guard).
//
// Keys are base58 and compared exactly: Solana addresses have no case to fold.
import type { OnchainLists } from "./inspection";

const DENYLIST = new Map<string, string>([
  // "<base58 address>" -> reason
]);

const ALLOWLIST = new Map<string, string>([]);

export interface ReputationResult {
  lane: "reputation";
  level: "LOW" | "HIGH";
  listed: "deny" | "allow" | null;
  reason: string;
}

export function checkReputation(recipient: string, onchain: OnchainLists | null = null): ReputationResult {
  if (DENYLIST.has(recipient)) {
    return { lane: "reputation", level: "HIGH", listed: "deny", reason: `On denylist: ${DENYLIST.get(recipient)}` };
  }
  if (onchain?.denied) {
    return { lane: "reputation", level: "HIGH", listed: "deny", reason: "Denylisted on-chain by the guard owner." };
  }
  if (ALLOWLIST.has(recipient)) {
    return { lane: "reputation", level: "LOW", listed: "allow", reason: `On allowlist: ${ALLOWLIST.get(recipient)}` };
  }
  return {
    lane: "reputation",
    level: "LOW",
    listed: null,
    reason: "No reputation record (mock lane - allow/deny lists are empty in V1).",
  };
}

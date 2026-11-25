// refusal codes: the same reason, in a form a program can read.
//
// Every refusal in this project already carries a prose reason, and prose is the
// right thing to put in front of a person - it has the numbers in it, and it can
// say "over its posted 100000" instead of making someone look that up. It is the
// wrong thing to branch on. An agent that should retry tomorrow when it hit the
// daily cap, and give up entirely when the recipient is denylisted, has to tell
// those apart somehow, and today the only way is to match a regular expression
// against a sentence that we reword whenever the wording reads badly and that
// has a merchant's own text interpolated into the middle of it.
//
// So every refusal carries a code beside its reason. Three rules keep the pair
// honest:
//
//  1. The code never decides anything. It is attached on the same line that
//     raised the refusal, so it cannot drift from the reason it labels, and
//     nothing in the firewall reads one back to make a decision. Adding this
//     changed no verdict anywhere - that is deliberate, and the tests that
//     already pinned those verdicts are the evidence.
//  2. The prose stays authoritative for humans. A code is a category. The reason
//     is what actually happened.
//  3. Unknown stays unknown. The mapping from AegisGuard's own on-chain strings
//     onto these codes returns UNKNOWN for anything it does not recognize rather
//     than guessing at the nearest match. A contract we deployed months ago is
//     allowed to say something this file has never seen.
//
// The codes are grouped by where they are raised, because "which layer refused"
// is usually the first thing you want to know. Every one of them is raised
// somewhere - test/refusals.test.mjs fails if a code stops being used, since a
// vocabulary that quietly accumulates dead words is worse than no vocabulary.

export const REFUSAL = Object.freeze({
  // ---- the policy engine's lanes (src/aegis.js) ----
  // these reach both rails: the x402 signer runs the same aegisCheck the
  // treasury CLI does, so a BLOCK here is the same BLOCK there.
  DENYLISTED: 'DENYLISTED',              // reputation lane says known bad
  HIGH_BYTECODE: 'HIGH_BYTECODE',        // opcode scan scored HIGH (and the LLM agreed, or was down)
  MEDIUM_BYTECODE: 'MEDIUM_BYTECODE',    // proxy / delegatecall / create2: not clearly safe
  LANES_DISAGREE: 'LANES_DISAGREE',      // scan says HIGH, LLM says benign - a human decides
  UNUSUAL_AMOUNT: 'UNUSUAL_AMOUNT',      // behavior lane: large, and unlike this recipient's history
  EOA_ALLOWANCE: 'EOA_ALLOWANCE',        // approving a plain wallet as a spender

  // ---- the x402 fetch wrapper, hook A (src/x402/fetch.js) ----
  // context the signer cannot see, because it never gets the 402.
  NO_PAYABLE_OPTION: 'NO_PAYABLE_OPTION', // nothing in `accepts` we could pay
  UNKNOWN_SERVICE: 'UNKNOWN_SERVICE',     // payTo is not in the catalog
  OVER_POSTED_PRICE: 'OVER_POSTED_PRICE', // bait-and-switch: demand above the posted price
  NO_APPROVER: 'NO_APPROVER',             // over the per-payment cap, nobody wired in to ask
  HUMAN_DECLINED: 'HUMAN_DECLINED',       // over the cap, a person said no
  APPROVER_FAILED: 'APPROVER_FAILED',     // over the cap, the prompt itself broke

  // ---- the x402 signer, hook B (src/x402/signer.js) ----
  // invariants re-derived from the authorization alone, whatever hook A thought.
  WRONG_ASSET: 'WRONG_ASSET',                         // not the canonical USDC
  WRONG_CHAIN: 'WRONG_CHAIN',                         // signed for another chain
  VALIDITY_WINDOW: 'VALIDITY_WINDOW',                 // expired, too long-lived, or starts later
  BAD_AMOUNT: 'BAD_AMOUNT',                           // non-positive value
  EXCEEDS_BALANCE: 'EXCEEDS_BALANCE',                 // more than the float holds
  MALFORMED_AUTHORIZATION: 'MALFORMED_AUTHORIZATION', // a field that isn't a number
  FUND_MOVING_PRIMITIVE: 'FUND_MOVING_PRIMITIVE',     // Permit and friends on the guarded token
  DISABLED_PRIMITIVE: 'DISABLED_PRIMITIVE',           // raw sign / signTransaction / 7702

  // ---- AegisGuard's own refusals, on-chain ----
  // the contract stores prose and is deployed and verified, so its strings are
  // mapped onto this vocabulary here rather than renamed there.
  ZERO_ADDRESS: 'ZERO_ADDRESS',
  BLOCKED_CODEHASH: 'BLOCKED_CODEHASH',
  UNVETTED_CONTRACT: 'UNVETTED_CONTRACT',
  DAILY_CAP: 'DAILY_CAP',
  NOT_AN_AGENT: 'NOT_AN_AGENT',           // guardedPay's first line: the caller was revoked
  TRANSFER_FAILED: 'TRANSFER_FAILED',     // policy passed, the token transfer didn't

  // ---- and the honest escape hatch ----
  UNKNOWN: 'UNKNOWN',
});

export const REFUSAL_CODES = Object.freeze(Object.values(REFUSAL));

export function isRefusalCode(value) {
  return typeof value === 'string' && Object.hasOwn(REFUSAL, value);
}

// AegisGuard.assess returns (Verdict, string). These are its five strings, and
// "clear" is the one that isn't a refusal at all.
const GUARD_REASONS = new Map([
  ['zero address', REFUSAL.ZERO_ADDRESS],
  ['recipient denylisted', REFUSAL.DENYLISTED],
  ['recipient code is blocklisted', REFUSAL.BLOCKED_CODEHASH],
  ['unvetted contract recipient', REFUSAL.UNVETTED_CONTRACT],
  ['over daily limit', REFUSAL.DAILY_CAP],
]);

// null for a clear verdict, UNKNOWN for anything this file doesn't recognize.
// Deliberately not fuzzy: a near-match would let a future contract change look
// like a code that means something else.
export function guardReasonCode(reason) {
  if (typeof reason !== 'string') return REFUSAL.UNKNOWN;
  const key = reason.trim().toLowerCase();
  if (key === 'clear') return null;
  return GUARD_REASONS.get(key) ?? REFUSAL.UNKNOWN;
}

// AegisGuard's custom errors, which are already machine-readable on their own -
// a custom error is a 4-byte selector, not a sentence. Mapping them here anyway
// is what makes "two rails, one policy engine" checkable: a revoked agent and a
// denylisted recipient come back in the same vocabulary whether the refusal
// happened in a contract or in a signer. `Denied` is the exception - it carries
// its own reason string, so guardReasonCode above is what reads it.
const GUARD_ERRORS = new Map([
  ['NotAgent', REFUSAL.NOT_AN_AGENT],
  ['TransferFailed', REFUSAL.TRANSFER_FAILED],
  ['ZeroAddress', REFUSAL.ZERO_ADDRESS],
]);

export function guardErrorCode(errorName) {
  if (typeof errorName !== 'string') return null;
  return GUARD_ERRORS.get(errorName.trim()) ?? null;
}

// ---- carrying a code through a string field ----
//
// AegisAuditLog stores one `reason` string per refusal and is already deployed,
// so the code rides at the front of that string rather than in a field of its
// own. Two things make that work rather than merely fit: the prefix is at the
// FRONT, so it is the part that survives trimReason cutting an oversized reason
// from the tail; and reading it back only recognizes codes this file defines, so
// a reason that happens to begin with something shaped like a code is treated as
// the prose it is.

const STAMPED = /^([A-Z][A-Z0-9_]*):\s+([\s\S]*)$/;

export function stampReason(code, reason) {
  const text = String(reason ?? '').trim();
  if (code == null) return text;                 // caller had no code to give
  const known = isRefusalCode(code) ? code : REFUSAL.UNKNOWN;
  return text ? `${known}: ${text}` : known;
}

// { code, reason } for a stamped string; { code: null, reason: <as written> }
// for anything else, which is what every entry written before this existed
// looks like.
export function readStamp(text) {
  const raw = String(text ?? '');
  const m = raw.match(STAMPED);
  if (m && isRefusalCode(m[1])) return { code: m[1], reason: m[2] };
  if (isRefusalCode(raw.trim())) return { code: raw.trim(), reason: '' };
  return { code: null, reason: raw };
}

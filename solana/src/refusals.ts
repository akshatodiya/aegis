// Refusal codes: the same reason, in a form a program can read.
//
// Ported from the EVM build with its three rules intact:
//  1. A code never decides anything. It is attached on the line that raised the
//     refusal, and nothing reads one back to make a decision.
//  2. The prose reason stays authoritative for humans. A code is a category.
//  3. Unknown stays unknown. Anything the maps below don't recognize is UNKNOWN,
//     never the nearest match.
//
// Every code here is raised somewhere; tests/unit/refusals.test.ts fails if one
// stops being used.

export const REFUSAL = Object.freeze({
  // ---- the policy engine's lanes (src/aegis.ts) ----
  DENYLISTED: "DENYLISTED", //                   reputation lane or the guard's deny list
  HIGH_RISK_ACCOUNT: "HIGH_RISK_ACCOUNT", //     inspection lane found a HIGH fact
  MEDIUM_RISK_ACCOUNT: "MEDIUM_RISK_ACCOUNT", // inspection lane found a MEDIUM fact
  UNUSUAL_AMOUNT: "UNUSUAL_AMOUNT", //           behavior lane: large, and unlike this recipient's history
  LANE_UNAVAILABLE: "LANE_UNAVAILABLE", //       the chain could not be read, so nothing is known

  // ---- the x402 fetch wrapper (src/x402/fetch.ts): context the signer can't see ----
  NO_PAYABLE_OPTION: "NO_PAYABLE_OPTION", //     nothing in `accepts` we could pay
  UNKNOWN_SERVICE: "UNKNOWN_SERVICE", //         payTo is not in the catalog
  OVER_POSTED_PRICE: "OVER_POSTED_PRICE", //     bait-and-switch: demand above the posted price
  NO_APPROVER: "NO_APPROVER", //                 over the per-payment cap, nobody there to ask
  HUMAN_DECLINED: "HUMAN_DECLINED", //           over the cap, a person said no
  APPROVER_FAILED: "APPROVER_FAILED", //         over the cap, the prompt itself broke

  // ---- the x402 signer (src/x402/signer.ts): re-derived from the transaction bytes ----
  MALFORMED_TRANSACTION: "MALFORMED_TRANSACTION", //   undecodable, legacy, lookup tables, wrong signer layout
  UNEXPECTED_INSTRUCTION: "UNEXPECTED_INSTRUCTION", // anything but the 4 payment instructions, or our key used elsewhere
  FEE_PAYER_IS_US: "FEE_PAYER_IS_US", //               the 402 would have us pay the network fees
  WRONG_ASSET: "WRONG_ASSET", //                       not USDC on the classic Token program, 6 decimals
  WRONG_NETWORK: "WRONG_NETWORK", //                   not the network we are configured for
  VALIDITY_WINDOW: "VALIDITY_WINDOW", //               blockhash not current on our RPC (expired, or another cluster)
  EXCEEDS_BALANCE: "EXCEEDS_BALANCE", //               more than the float holds
  BAD_MEMO: "BAD_MEMO", //                             a memo that isn't an invoice id (decision 6)
  SIMULATION_MISMATCH: "SIMULATION_MISMATCH", //       simulation failed, or moved anything but exactly the payment
  DISABLED_PRIMITIVE: "DISABLED_PRIMITIVE", //         raw message signing

  // ---- aegis_guard's own refusals, on-chain (mapped from its IDL error names) ----
  NOT_AN_AGENT: "NOT_AN_AGENT",
  PAUSED: "PAUSED",
  BAD_AMOUNT: "BAD_AMOUNT",
  SINK_RECIPIENT: "SINK_RECIPIENT",
  PROGRAM_RECIPIENT: "PROGRAM_RECIPIENT",
  TOKEN_ACCOUNT_RECIPIENT: "TOKEN_ACCOUNT_RECIPIENT",
  SYSVAR_RECIPIENT: "SYSVAR_RECIPIENT",
  BLOCKED_PROGRAM: "BLOCKED_PROGRAM",
  UNVETTED_PROGRAM_RECIPIENT: "UNVETTED_PROGRAM_RECIPIENT",
  BAD_DESTINATION: "BAD_DESTINATION",
  DESTINATION_OWNER_MISMATCH: "DESTINATION_OWNER_MISMATCH",
  FROZEN_DESTINATION: "FROZEN_DESTINATION",
  DELEGATED_DESTINATION: "DELEGATED_DESTINATION",
  DAILY_CAP: "DAILY_CAP",
  TRANSFER_FAILED: "TRANSFER_FAILED", //         policy passed, the token program's transfer didn't

  // ---- and the honest escape hatch ----
  UNKNOWN: "UNKNOWN",
});

export type RefusalCode = (typeof REFUSAL)[keyof typeof REFUSAL];

export const REFUSAL_CODES: readonly RefusalCode[] = Object.freeze(Object.values(REFUSAL));

export function isRefusalCode(value: unknown): value is RefusalCode {
  return typeof value === "string" && Object.prototype.hasOwnProperty.call(REFUSAL, value);
}

// aegis_guard's error names (the IDL's `errors[].name`) for a refused payment.
// The first block of AegisError mirrors the `Reason` enum that `assess` returns,
// so the same refusal carries the same code on both paths.
const GUARD_ERRORS = new Map<string, RefusalCode>([
  ["NotAgent", REFUSAL.NOT_AN_AGENT],
  ["Paused", REFUSAL.PAUSED],
  ["BadAmount", REFUSAL.BAD_AMOUNT],
  ["SinkRecipient", REFUSAL.SINK_RECIPIENT],
  ["Denylisted", REFUSAL.DENYLISTED],
  ["ProgramRecipient", REFUSAL.PROGRAM_RECIPIENT],
  ["TokenAccountRecipient", REFUSAL.TOKEN_ACCOUNT_RECIPIENT],
  ["SysvarRecipient", REFUSAL.SYSVAR_RECIPIENT],
  ["BlockedProgram", REFUSAL.BLOCKED_PROGRAM],
  ["UnvettedProgramRecipient", REFUSAL.UNVETTED_PROGRAM_RECIPIENT],
  ["BadDestination", REFUSAL.BAD_DESTINATION],
  ["DestinationOwnerMismatch", REFUSAL.DESTINATION_OWNER_MISMATCH],
  ["FrozenDestination", REFUSAL.FROZEN_DESTINATION],
  ["DelegatedDestination", REFUSAL.DELEGATED_DESTINATION],
  ["DailyCap", REFUSAL.DAILY_CAP],
]);

/**
 * Guard errors that are not a payment refusal: admin gates and malformed calls.
 * Listed so the IDL test can tell "deliberately not a refusal" from "forgotten".
 */
export const GUARD_ERRORS_NOT_REFUSALS: readonly string[] = Object.freeze([
  "NotOwner",
  "NotPendingOwner",
  "NotUpgradeAuthority",
  "NotReporter",
  "BadEntryAccount",
  "MissingControllerEntry",
  "BadReason",
  "BadCode",
  "BadVault",
  "MathOverflow",
]);

/** The code for an aegis_guard error name; null for a non-refusal error; UNKNOWN for a name this file has never seen. */
export function guardErrorCode(errorName: unknown): RefusalCode | null {
  if (typeof errorName !== "string") return REFUSAL.UNKNOWN;
  const name = errorName.trim();
  const code = GUARD_ERRORS.get(name);
  if (code) return code;
  if (GUARD_ERRORS_NOT_REFUSALS.includes(name)) return null;
  return REFUSAL.UNKNOWN;
}

/**
 * The code for an `assess` reason, as Anchor's TS client names enum variants
 * (`denylisted`, `dailyCap`, ...). null for `clear`, UNKNOWN for anything else.
 */
export function guardReasonCode(reason: unknown): RefusalCode | null {
  if (typeof reason !== "string") return REFUSAL.UNKNOWN;
  const key = reason.trim();
  if (key === "clear") return null;
  const pascal = key.charAt(0).toUpperCase() + key.slice(1);
  return GUARD_ERRORS.get(pascal) ?? REFUSAL.UNKNOWN;
}

const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/**
 * The code for a failed `guarded_pay` transaction, from whatever the client
 * threw or the landed transaction's logs. Only our own program's named error, or
 * a failure inside the token program, gets a specific code.
 */
export function guardFailureCode(programId: string, err: unknown, logs: string[] = []): RefusalCode | null {
  const e = err as any;
  // AnchorError from @anchor-lang/core carries the raising program and the error name.
  const named = e?.error?.errorCode?.code;
  if (typeof named === "string") {
    const from = e?.program?.toString?.();
    if (!from || from === programId) return guardErrorCode(named);
    return REFUSAL.UNKNOWN; // another program's error; its logs would only repeat it
  }
  const all = [...logs, ...(e?.logs ?? []), ...(e?.transactionLogs ?? [])].map(String);
  // An AnchorError line belongs to whichever program is running when it is
  // logged, so follow the invoke/success/failed stack and take only ours.
  const stack: string[] = [];
  for (const line of all) {
    const invoke = /^Program (\w+) invoke \[\d+\]/.exec(line);
    if (invoke) {
      stack.push(invoke[1]);
      continue;
    }
    if (/^Program \w+ (success|failed)/.test(line)) {
      stack.pop();
      continue;
    }
    const m = /^Program log: AnchorError .*Error Code: (\w+)\./.exec(line);
    if (m && stack[stack.length - 1] === programId) return guardErrorCode(m[1]);
  }
  if (all.some((l) => l.startsWith(`Program ${TOKEN_PROGRAM_ID} failed`))) return REFUSAL.TRANSFER_FAILED;
  return REFUSAL.UNKNOWN;
}

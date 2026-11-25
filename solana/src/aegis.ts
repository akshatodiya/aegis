// The decision engine. Deterministic lanes first; the LLM only explains, when a
// human is about to be asked. Returns one of PAY / BLOCK / ASK_HUMAN.
//
//   denylisted (mock list or the guard's own)  -> BLOCK      DENYLISTED
//   inspection HIGH (exact account facts)      -> BLOCK      HIGH_RISK_ACCOUNT   (no LLM: analyze-only)
//   inspection could not read the chain        -> ASK_HUMAN  LANE_UNAVAILABLE
//   inspection MEDIUM                          -> ASK_HUMAN  MEDIUM_RISK_ACCOUNT (LLM explains)
//   behavior: large and unlike history         -> ASK_HUMAN  UNUSUAL_AMOUNT      (LLM explains)
//   behavior: large, history unknown           -> ASK_HUMAN  LANE_UNAVAILABLE    (LLM explains)
//   otherwise                                  -> PAY
//
// The guard's lists and history are part of the check. With no guard id found
// (no AEGIS_PROGRAM_ID, no built IDL) it fails closed as LANE_UNAVAILABLE;
// `guard: null` opts out explicitly, and the verdict then says what was skipped.
//
// On EVM a HIGH went to the LLM, which could downgrade it to ASK_HUMAN. Here the
// HIGH facts are exact reads (an account's owner, a frozen flag), not an
// over-approximating opcode scan, so they block by themselves (decision 7).
import { Connection, PublicKey } from "@solana/web3.js";

import { AccountReader, connectionReader } from "./chain/reader";
import { guardProgramId, rpcUrl } from "./config";
import { BehaviorResult, checkBehavior } from "./lanes/behavior";
import { Inspection, inspect } from "./lanes/inspection";
import { ReputationResult, checkReputation } from "./lanes/reputation";
import { LlmResult, Reasoner, claudeReasoner } from "./reasoning";
import { REFUSAL, RefusalCode } from "./refusals";
import { formatUnits, toBaseUnits } from "./units";

export const DECISION = Object.freeze({
  PAY: "PAY",
  BLOCK: "BLOCK",
  ASK_HUMAN: "ASK_HUMAN",
} as const);

export type Decision = (typeof DECISION)[keyof typeof DECISION];

export interface AegisOptions {
  /** Where lanes read chain state. Default: the RPC from AEGIS_RPC_URL / ANCHOR_PROVIDER_URL / devnet. */
  reader?: AccountReader;
  /** aegis_guard program id for the on-chain lists and payment history. undefined = from env/IDL (none found fails closed); null = run without them. */
  guard?: PublicKey | null;
  /** The LLM explainer. undefined = `claude -p`; null = never call one. */
  reasoner?: Reasoner | null;
  /** Explicit destination token account (x402). Default: ATA(recipient, USDC). */
  destination?: PublicKey;
  /** An asset other than USDC to inspect (x402 offers). */
  mint?: PublicKey;
  /** Override the pinned USDC mint (tests only). */
  usdcMint?: PublicKey;
  /** See InspectOptions.recentDeploySlots. */
  recentDeploySlots?: number;
}

export interface AegisResult {
  decision: Decision;
  /** Why this wasn't simply paid, for programs. null on PAY. */
  code: RefusalCode | null;
  reasons: string[];
  lanes: { inspection: Inspection; reputation: ReputationResult; behavior: BehaviorResult };
  llm: LlmResult | null;
  recipient: string;
  /** Decimal USDC, as displayed. */
  amount: string;
  /** Base units, as the chain moves them. */
  amountUnits: bigint;
}

export async function aegisCheck(recipient: PublicKey | string, amount: string | number, opts: AegisOptions = {}): Promise<AegisResult> {
  const recipientKey = new PublicKey(recipient);
  const units = toBaseUnits(amount);
  // The guard refuses a zero payment (BadAmount); so does the engine.
  if (units === 0n) throw new Error("amount must be greater than zero");
  const shown = formatUnits(units);
  const reader = opts.reader ?? connectionReader(new Connection(rpcUrl(), "confirmed"));
  const guard = opts.guard === undefined ? guardProgramId() : opts.guard;
  const guardMissing = opts.guard === undefined && guard === null;
  const reasoner = opts.reasoner === undefined ? claudeReasoner() : opts.reasoner;

  const [inspection, behavior] = await Promise.all([
    inspect(recipientKey, {
      reader,
      guard,
      amount: units,
      destination: opts.destination,
      mint: opts.mint,
      usdcMint: opts.usdcMint,
      recentDeploySlots: opts.recentDeploySlots,
    }),
    checkBehavior(reader, guard, recipientKey, units),
  ]);
  const reputation = checkReputation(recipientKey.toBase58(), inspection.onchain);

  const lanes = { inspection, reputation, behavior };
  const reasons: string[] = [];
  let decision: Decision;
  let code: RefusalCode | null = null;
  let llm: LlmResult | null = null;

  const explain = async (trigger: string) => {
    if (!reasoner) {
      reasons.push("   (no LLM configured - escalating on deterministic grounds.)");
      return;
    }
    reasons.push("Asking the LLM to explain the findings for the human...");
    llm = await reasoner({ recipient: recipientKey.toBase58(), amount: shown, trigger, facts: inspection.facts });
    if (llm.available) reasons.push(`LLM summary (model output, risk ${llm.risk ?? "unrated"}): ${llm.summary}`);
    else reasons.push(`   (LLM unavailable: ${llm.error} - escalating on deterministic grounds.)`);
  };

  if (reputation.listed !== "deny" && guardMissing && inspection.level !== "HIGH") {
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.LANE_UNAVAILABLE;
    reasons.push(
      "No aegis_guard program id was found (set AEGIS_PROGRAM_ID, or build so target/idl exists), so its deny list and payment history could not be read. Pass guard: null to run without them."
    );
  } else if (reputation.listed === "deny") {
    decision = DECISION.BLOCK;
    code = REFUSAL.DENYLISTED;
    reasons.push(`Reputation: ${reputation.reason}`);
  } else if (inspection.level === "HIGH") {
    decision = DECISION.BLOCK;
    code = REFUSAL.HIGH_RISK_ACCOUNT;
    reasons.push(`Inspection flagged HIGH: ${inspection.reason}`);
    reasons.push("   (HIGH facts are exact account reads, so they block without an LLM second opinion.)");
  } else if (inspection.level === "UNKNOWN") {
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.LANE_UNAVAILABLE;
    reasons.push(`Inspection: ${inspection.reason}`);
  } else if (inspection.level === "MEDIUM") {
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.MEDIUM_RISK_ACCOUNT;
    reasons.push(`Inspection flagged MEDIUM: ${inspection.reason}`);
    await explain(inspection.reason);
  } else if (behavior.escalate) {
    decision = DECISION.ASK_HUMAN;
    code = behavior.history === null ? REFUSAL.LANE_UNAVAILABLE : REFUSAL.UNUSUAL_AMOUNT;
    reasons.push(`Behavior: ${behavior.reason}`);
    await explain(behavior.reason);
  } else {
    decision = DECISION.PAY;
    reasons.push(`Inspection: ${inspection.reason}`);
    if (reputation.listed === "allow") reasons.push(`Reputation: ${reputation.reason}`);
  }
  if (guard === null && !guardMissing) {
    reasons.push("   (No guard configured: its deny/allow lists and payment history were not consulted.)");
  }

  return { decision, code, reasons, lanes, llm, recipient: recipientKey.toBase58(), amount: shown, amountUnits: units };
}

function banner(decision: Decision): string {
  return {
    PAY: "\x1b[42m\x1b[30m  PAY  \x1b[0m",
    BLOCK: "\x1b[41m\x1b[37m  BLOCK  \x1b[0m",
    ASK_HUMAN: "\x1b[43m\x1b[30m  ASK_HUMAN  \x1b[0m",
  }[decision];
}

export function formatVerdict(result: AegisResult): string {
  const { decision, code, reasons, recipient, amount } = result;
  const lines = [
    "",
    "----------------------------------------------",
    `  AEGIS verdict for ${recipient}`,
    `  amount: ${amount} USDC`,
    "----------------------------------------------",
    `  ${banner(decision)}${code ? `  ${code}` : ""}`,
    "",
    ...reasons.map((r) => `  ${r}`),
    "----------------------------------------------",
    "",
  ];
  return lines.join("\n");
}

export function printVerdict(result: AegisResult): void {
  console.log(formatVerdict(result));
}

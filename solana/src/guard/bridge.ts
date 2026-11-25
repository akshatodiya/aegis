// The bridge between the off-chain verdict and the guard's on-chain lists.
//
// Same asymmetry as the EVM build:
//  - BLOCK is written automatically. It only tightens policy, so the worst a
//    wrong call does is refuse a payment, which the owner undoes with one write.
//    It reads the exact entry first, so a re-run says "already blocked".
//  - ALLOW is never automatic. It grants trust, so the owner has to say yes,
//    no TTY means no, and the payment goes out only if the guard's own
//    assessment then reads PAY.
//
// Which list a BLOCK goes to depends on what the finding is about:
//  - a program-level finding (closed program, blocked program) blocks the
//    program id, which catches every account it owns, including future ones;
//  - a finding about the recipient or its USDC account denylists that address;
//  - a recipient type the guard already refuses (a program, a mint, a token
//    account, a sysvar, a sink) needs no write;
//  - a mint finding maps to no list: the guard only ever moves USDC.
// A program-level block is written even when the recipient is already
// denylisted: it also covers the program's other accounts. Registry programs
// (System, Token, the loaders, ...) and the guard itself are never written to
// `blockprog`; that would refuse ordinary accounts.
//
// Only states the recipient itself controls ever reach `deny`. A state a
// stranger can create (lamports sent to a wallet's ATA address) is not HIGH in
// the inspection lane, so it can't get an innocent wallet denylisted.
import { Keypair, PublicKey } from "@solana/web3.js";
import { createInterface } from "readline/promises";

import type { AegisResult } from "../aegis";
import type { Inspection } from "../lanes/inspection";
import { REFUSAL } from "../refusals";
import { knownProgram } from "../registry";
import { formatUnits } from "../units";
import type { GuardClient, SendOutcome } from "./client";
import type { EntryKind } from "./layout";

export type BlockTarget =
  | { kind: "deny" | "blockprog"; key: PublicKey; why: string }
  | { kind: "none"; why: string };

export function blockTarget(result: AegisResult, guardProgram: PublicKey): BlockTarget {
  if (result.decision !== "BLOCK") return { kind: "none", why: `nothing to record: the verdict is ${result.decision}, and only a BLOCK is written.` };
  const recipient = new PublicKey(result.recipient);
  const high = result.lanes.inspection.facts.filter((f) => f.level === "HIGH");

  const programFact = high.find(
    (f) => f.subject === "program" && typeof f.data?.program === "string" && !isProtectedProgram(new PublicKey(f.data.program as string), guardProgram)
  );
  if (programFact) {
    const program = new PublicKey(programFact.data!.program as string);
    return { kind: "blockprog", key: program, why: `${programFact.id}: blocking program ${program.toBase58()} refuses every account it controls` };
  }
  if (result.code === REFUSAL.DENYLISTED) {
    return { kind: "deny", key: recipient, why: "the reputation lane denylists it" };
  }
  if (high.some((f) => f.guardEnforced)) {
    return { kind: "none", why: "aegis_guard already refuses this recipient type on-chain by itself; nothing to record." };
  }
  if (high.some((f) => f.subject === "recipient" || f.subject === "destination" || f.subject === "program")) {
    return { kind: "deny", key: recipient, why: high.map((f) => f.id).join(", ") };
  }
  return { kind: "none", why: "the findings are about a mint, which no guard list covers: the guard only moves USDC." };
}

export function isProtectedProgram(program: PublicKey, guardProgram: PublicKey): boolean {
  return program.equals(guardProgram) || knownProgram(program) !== null;
}

export interface BridgeOutcome {
  changed: boolean;
  message: string;
  signature?: string;
  target?: BlockTarget;
}

const LIST_NAME: Record<EntryKind, string> = {
  deny: "denylisted",
  blockprog: "blocked (program)",
  allow: "allowlisted",
  agent: "an agent",
  reporter: "a reporter",
};

/** Write a BLOCK verdict into the guard's lists. Idempotent; never throws. Needs the owner key. */
export async function recordVerdictOnChain(client: GuardClient, owner: Keypair, result: AegisResult): Promise<BridgeOutcome> {
  const target = blockTarget(result, client.programId);
  if (target.kind === "none") return { changed: false, message: target.why, target };
  return writeEntry(client, owner, target.kind, target.key, null, target);
}

async function writeEntry(
  client: GuardClient,
  owner: Keypair,
  kind: EntryKind,
  key: PublicKey,
  controller: PublicKey | null,
  target?: BlockTarget
): Promise<BridgeOutcome> {
  const label = `${key.toBase58()} is ${LIST_NAME[kind]}`;
  try {
    // Idempotency reads the exact entry about to be written, not assess(): the
    // recipient could already be refused for another reason while this entry
    // is missing.
    const before = await client.entry(kind, key);
    if (before.member) return { changed: false, message: `already recorded on-chain: ${label}.`, target };
    const sent: SendOutcome = await client.addEntry(owner, kind, key, controller);
    if (sent.landed === false) return { changed: false, message: `could not record on-chain: ${sent.error}`, target };
    // Landed, or could not tell: the entry itself is the answer.
    const after = await client.entry(kind, key);
    if (after.member) return { changed: true, message: `recorded on-chain: ${label}.`, signature: sent.signature ?? undefined, target };
    if (sent.ok) return { changed: false, message: `the write landed (${sent.signature}) but the entry is not there; not claiming it.`, target };
    return { changed: false, message: `could not record on-chain: ${sent.error}`, target };
  } catch (err: any) {
    return { changed: false, message: `could not record on-chain: ${err?.message ?? String(err)}`, target };
  }
}

export interface VettingOffer {
  offer: boolean;
  controller: PublicKey | null;
  why: string;
}

/**
 * Whether to offer the owner an allowlist for this recipient, computed from the
 * inspection's state rather than from an error string.
 *
 * Who can move the USDC decides it, not who owns the recipient's data:
 *  - on the curve, a keypair signs for the USDC account, whatever program owns
 *    the data. Offered with no controller, and the question says so.
 *  - off the curve, only the program that derived the address can sign, and
 *    the data owner need not be that program (the deriving program can assign
 *    it to any program). Nothing on-chain proves which program it is, so
 *    Aegis offers nothing: the owner names the controller themselves, with
 *    `allowlistOnChain`, once they have checked it.
 */
export function needsVetting(inspection: Inspection): VettingOffer {
  const no = (why: string): VettingOffer => ({ offer: false, controller: null, why });
  if (inspection.level === "UNKNOWN") return no("the recipient could not be read, so there is nothing to vet.");
  if (inspection.kind !== "program-owned" && inspection.kind !== "pda") return no("the guard does not ask to vet this kind of recipient.");
  if (inspection.onchain?.allow) return no("already allowlisted on-chain.");
  if (inspection.facts.some((f) => f.level === "HIGH")) return no("it has HIGH findings; it is not a vetting question.");
  if (!PublicKey.isOnCurve(new PublicKey(inspection.recipient).toBytes())) {
    return no(
      "only the program that derived this address can move its USDC, and nothing on-chain says which program that is (its data owner need not be it). Aegis does not offer an allowlist that would name a program nobody verified."
    );
  }
  return { offer: true, controller: null, why: "a keypair address whose data a program owns; the guard has not been told to trust it" };
}

/**
 * Writes an allow entry. `controller` is the program that signs for an
 * off-curve recipient's USDC account; a later block on it still wins. Only name
 * one you have verified (e.g. the address re-derives from its seeds under it).
 */
export async function allowlistOnChain(client: GuardClient, owner: Keypair, recipient: PublicKey, controller: PublicKey | null): Promise<BridgeOutcome> {
  return writeEntry(client, owner, "allow", recipient, controller);
}

export type Confirm = (question: string) => Promise<boolean>;

/** Ask the person at the keyboard. No TTY (piped, CI, a script) means no. */
export const confirmOwner: Confirm = async (question) => {
  if (!process.stdin.isTTY) {
    console.log(`  (${question} - no interactive owner present, defaulting to no.)`);
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} (y/N) `)).trim().toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
};

export interface VetOutcome {
  paid: boolean;
  messages: string[];
  pay?: SendOutcome;
}

/**
 * A program-controlled recipient the lanes judged fine but the guard has never
 * been told to trust: ask the owner, allowlist on a yes, re-read the guard's
 * own verdict, and pay only if it now reads PAY.
 */
export async function vetThenPay(
  client: GuardClient,
  keys: { owner: Keypair; agent: Keypair },
  result: AegisResult,
  confirm: Confirm = confirmOwner
): Promise<VetOutcome> {
  const messages: string[] = [];
  const recipient = new PublicKey(result.recipient);
  if (result.decision !== "PAY") {
    return { paid: false, messages: [`not offering an allowlist: the off-chain verdict is ${result.decision}${result.code ? ` / ${result.code}` : ""}, not PAY.`] };
  }
  const vet = needsVetting(result.lanes.inspection);
  if (!vet.offer) return { paid: false, messages: [`not offering an allowlist: ${vet.why}`] };

  const owners = result.lanes.inspection.programs.map((p) => `${p.id}${p.name ? ` (${p.name})` : ""}`).join(", ");
  const question = `Allowlist ${recipient.toBase58()} on-chain and pay it ${result.amount} USDC? It is a keypair address, so whoever holds that key moves the USDC; its data is owned by ${owners || "a program"}.`;
  if (!(await confirm(question))) {
    return { paid: false, messages: ["leaving it at REVIEW, no payment sent."] };
  }
  const vetted = await allowlistOnChain(client, keys.owner, recipient, vet.controller);
  messages.push(vetted.message);
  if (!vetted.changed && !/already recorded/.test(vetted.message)) return { paid: false, messages: [...messages, "not paying."] };

  const after = await preview(client, recipient, result.amountUnits, messages, "now");
  if (after?.verdict !== "PAY") {
    messages.push("not PAY on-chain, not sending.");
    return { paid: false, messages };
  }
  const pay = await client.guardedPay(keys.agent, recipient, result.amountUnits);
  messages.push(payMessage(pay, `paid ${formatUnits(result.amountUnits)} USDC through the guard`));
  return { paid: pay.ok, messages, pay };
}

export interface ActOutcome {
  action:
    | "paid"
    | "vetted" //             allowlisted on a yes, then paid
    | "not-sent" //           nothing went to the chain
    | "pay-failed" //         landed and failed: fee paid, no USDC moved
    | "pay-unknown" //        could not tell whether it landed; check pay.signature before retrying
    | "recorded-block" //     the BLOCK is now in the guard's lists
    | "blocked-no-write" //   BLOCK, and no write is needed (already there, or no list covers it)
    | "block-not-recorded" // BLOCK, but the write failed or there was no owner key
    | "asked-human";
  messages: string[];
  pay?: SendOutcome;
  bridge?: BridgeOutcome;
}

/** The guard's own verdict, for the log. Informational: a failure is noted, never thrown. */
async function preview(client: GuardClient, recipient: PublicKey, amountUnits: bigint, messages: string[], when = "") {
  try {
    const a = await client.assess(recipient, amountUnits);
    messages.push(`on-chain assess()${when ? ` ${when}` : ""}: ${a.verdict}${a.code ? ` / ${a.code}` : ""} (${a.reason})`);
    return a;
  } catch (err: any) {
    messages.push(`on-chain assess()${when ? ` ${when}` : ""} could not be read: ${err?.message ?? String(err)}`);
    return null;
  }
}

function payMessage(pay: SendOutcome, success: string): string {
  if (pay.ok) return `${success}: ${pay.signature}`;
  if (pay.landed === null) return `UNKNOWN whether the payment landed (${pay.error}). Check ${pay.signature} before retrying.`;
  if (pay.landed) return `payment landed and failed (fee paid, no USDC moved): ${pay.code ?? ""} ${pay.error}`;
  return `payment not sent: ${pay.code ?? ""} ${pay.error}`;
}

function payAction(pay: SendOutcome, success: "paid" | "vetted"): ActOutcome["action"] {
  if (pay.ok) return success;
  if (pay.landed === null) return "pay-unknown";
  return pay.landed ? "pay-failed" : "not-sent";
}

/**
 * The treasury rail end to end, as the EVM `runGuard` did it: show the guard's
 * own verdict, then act on the off-chain decision.
 *   PAY       -> pay through the guard, or offer vetting if the guard says REVIEW
 *   BLOCK     -> record it on-chain so the guard enforces it by itself; send nothing
 *   ASK_HUMAN -> stop; a person decides
 * Returns an outcome for every case; it does not throw.
 */
export async function actOnVerdict(
  client: GuardClient,
  keys: { owner: Keypair | null; agent: Keypair },
  result: AegisResult,
  confirm: Confirm = confirmOwner
): Promise<ActOutcome> {
  const recipient = new PublicKey(result.recipient);
  const messages: string[] = [];

  if (result.decision === "BLOCK") {
    // Record first: the preview is only for the log.
    await preview(client, recipient, result.amountUnits, messages);
    if (!keys.owner) {
      messages.push("BLOCK, and no owner key in this process to record it on-chain. Nothing sent.");
      return { action: "block-not-recorded", messages };
    }
    const bridge = await recordVerdictOnChain(client, keys.owner, result);
    messages.push(bridge.message);
    if (bridge.changed) await preview(client, recipient, result.amountUnits, messages, "now");
    messages.push("transaction NOT sent.");
    const written = bridge.target?.kind === "none" || /^already recorded/.test(bridge.message);
    return { action: bridge.changed ? "recorded-block" : written ? "blocked-no-write" : "block-not-recorded", messages, bridge };
  }

  if (result.decision === "ASK_HUMAN") {
    await preview(client, recipient, result.amountUnits, messages);
    messages.push("ASK_HUMAN: pausing for a person, nothing sent.");
    return { action: "asked-human", messages };
  }

  const before = await preview(client, recipient, result.amountUnits, messages);
  if (!before) {
    messages.push("not sending without the guard's own verdict.");
    return { action: "not-sent", messages };
  }
  if (before.verdict === "PAY") {
    const pay = await client.guardedPay(keys.agent, recipient, result.amountUnits);
    messages.push(payMessage(pay, "paid through the guard"));
    return { action: payAction(pay, "paid"), messages, pay };
  }
  if (before.verdict === "REVIEW" && before.reason === "unvettedProgramRecipient" && keys.owner) {
    const vet = await vetThenPay(client, { owner: keys.owner, agent: keys.agent }, result, confirm);
    return { action: vet.pay ? payAction(vet.pay, "vetted") : "not-sent", messages: [...messages, ...vet.messages], pay: vet.pay };
  }
  messages.push(`the guard is stricter here (${before.verdict}), not sending a transaction we know would fail.`);
  return { action: "not-sent", messages };
}

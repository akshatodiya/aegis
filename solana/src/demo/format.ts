import { Connection } from "@solana/web3.js";

import { formatUnits } from "../units";
import { DemoResult, explorerUrl } from "./common";

const TITLES: Record<DemoResult["beat"], string> = {
  good: "Good recipient",
  delegated: "Delegated recipient",
  "bad-mint": "Look-alike mint over x402",
  drain: "Injected drain",
  kill: "Kill switch",
};

/** Keeps stage output short. The beat functions return data and never print. */
export async function formatDemo(
  connection: Connection,
  result: DemoResult
): Promise<string> {
  const lines = [
    `${TITLES[result.beat]}: ${result.ok ? "expected result" : "FAILED"}`,
  ];
  for (const v of result.verdicts)
    lines.push(`  ${v.label}: ${v.decision}${v.code ? ` / ${v.code}` : ""}`);
  if (result.beat === "delegated") {
    const delegate = result.facts.find((f) => f.id === "DELEGATED_DESTINATION");
    if (delegate) lines.push(`  ${delegate.level} fact: ${delegate.detail}`);
    lines.push(
      result.details.bridgeChanged
        ? "  The bridge recorded the deny entry."
        : result.details.alreadyBlocked
        ? "  The villain was already blocked; no new deny write."
        : "  The bridge could not record the deny entry."
    );
  }
  if (result.beat === "bad-mint") {
    for (const f of result.facts.filter((x) =>
      [
        "NOT_PINNED_ASSET",
        "PERMANENT_DELEGATE",
        "FREEZE_AUTHORITY",
        "SPOOFED_METADATA",
      ].includes(x.id)
    ))
      lines.push(`  ${f.id}: ${f.detail}`);
    lines.push(
      `  x402 wallet SOL: ${result.details.floatSol ?? "unknown"} lamports`
    );
  }
  if (result.beat === "good" && result.balances.vaultBefore !== undefined) {
    lines.push(
      `  Vault ${formatUnits(
        result.balances.vaultBefore ?? 0n
      )} → ${formatUnits(
        result.balances.vaultAfter ?? 0n
      )} USDC; recipient ${formatUnits(
        result.balances.recipientBefore ?? 0n
      )} → ${formatUnits(result.balances.recipientAfter ?? 0n)} USDC.`
    );
  }
  if (result.beat === "drain" && result.balances.vaultAfter !== undefined) {
    const before = result.balances.vaultBefore;
    const after = result.balances.vaultAfter;
    const failed = result.transactions.some((tx) => tx.outcome === "failed");
    if (before === undefined)
      lines.push(`  Vault balance: ${formatUnits(after)} USDC.`);
    else if (before === after)
      lines.push(`  Vault stayed at ${formatUnits(after)} USDC${failed ? "; the failed transaction is public" : ""}.`);
    else
      lines.push(`  Vault moved from ${formatUnits(before)} to ${formatUnits(after)} USDC; the expected block failed.`);
  }
  if (result.beat === "kill")
    lines.push(
      `  Agent restored: ${result.details.restored === true ? "yes" : "NO"}.`
    );
  for (const note of result.notes) lines.push(`  ${note}`);
  for (const tx of result.transactions)
    lines.push(
      `  ${tx.label} (${tx.outcome}): ${await explorerUrl(
        connection,
        tx.signature
      )}`
    );
  return lines.join("\n");
}

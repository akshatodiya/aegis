import { getAccount } from "@solana/spl-token";
import { Connection, PublicKey } from "@solana/web3.js";
import { AddressInfo } from "net";

import { aegisCheck } from "../aegis";
import { createAuditLogger } from "../audit";
import { connectionReader } from "../chain/reader";
import { caip2, USDC_MINT } from "../config";
import { ensureFloat } from "../float";
import { recordVerdictOnChain } from "../guard/bridge";
import { GuardClient, SendOutcome } from "../guard/client";
import { associatedTokenAddress } from "../guard/layout";
import { REFUSAL } from "../refusals";
import { formatUnits } from "../units";
import { createCatalog } from "../x402/catalog";
import { createAegisX402Fetch } from "../x402/fetch";
import { createMerchant } from "../x402/merchant";
import { AegisPaymentRefused } from "../x402/refused";
import { connectionRpc } from "../x402/rpc";
import { createAegisSigner } from "../x402/signer";
import {
  DemoKeys,
  DemoOptions,
  DemoResult,
  demoResult,
  needKey,
} from "./common";
import { restoreAgentEntry } from "./recovery";

const GOOD_AMOUNT = 1_000_000n;
const BAD_AMOUNT = 3_000_000n;
const X402_PRICE = 50_000n;

const policy = (
  connection: Connection,
  programId: PublicKey,
  recipient: PublicKey,
  amount: bigint
) =>
  aegisCheck(recipient, formatUnits(amount), {
    reader: connectionReader(connection),
    guard: programId,
    reasoner: null,
    recentDeploySlots: 0,
  });

function notePay(result: DemoResult, label: string, pay: SendOutcome) {
  if (pay.signature && pay.landed !== false)
    result.transactions.push({
      label,
      signature: pay.signature,
      outcome: pay.ok
        ? "succeeded"
        : pay.landed === true
        ? "failed"
        : "unknown",
    });
  if (pay.error && (pay.landed !== true || !pay.code))
    result.notes.push(`${label}: ${pay.error}`);
}

const usdcBalance = async (connection: Connection, account: PublicKey) =>
  (await getAccount(connection, account)).amount;

/** A clean wallet passes the off-chain check, and only guarded_pay moves USDC. */
export async function goodRecipient(
  connection: Connection,
  keys: DemoKeys,
  opts: DemoOptions
): Promise<DemoResult> {
  const result = demoResult("good");
  const agent = needKey(keys.agent, "agent");
  const recipient = needKey(keys.good, "good recipient");
  const client = new GuardClient(connection, opts.programId, agent.publicKey);
  const cfg = await client.config();
  if (!cfg)
    throw new Error("the guard is not initialized; run yarn demo:setup");
  const amount = opts.amount ?? GOOD_AMOUNT;
  const destination = associatedTokenAddress(recipient, cfg.mint);
  const verdict = await policy(connection, opts.programId, recipient, amount);
  result.verdicts.push({
    label: "Aegis",
    decision: verdict.decision,
    code: verdict.code,
  });
  if (verdict.decision !== "PAY") return result;
  const assessment = await client.assess(recipient, amount);
  result.verdicts.push({
    label: "guard assess",
    decision: assessment.verdict,
    code: assessment.code,
  });
  if (assessment.verdict !== "PAY") return result;
  result.balances.vaultBefore = await usdcBalance(connection, cfg.vault);
  result.balances.recipientBefore = await usdcBalance(connection, destination);
  const pay = await client.guardedPay(agent, recipient, amount);
  notePay(result, "guarded payment", pay);
  result.balances.vaultAfter = await usdcBalance(connection, cfg.vault);
  result.balances.recipientAfter = await usdcBalance(connection, destination);
  result.ok =
    pay.ok &&
    result.balances.vaultBefore - result.balances.vaultAfter === amount &&
    result.balances.recipientAfter - result.balances.recipientBefore === amount;
  return result;
}

/** A pre-existing delegate is visible; the bridge then makes the block durable. */
export async function delegatedRecipient(
  connection: Connection,
  keys: DemoKeys,
  opts: DemoOptions
): Promise<DemoResult> {
  const result = demoResult("delegated");
  const owner = needKey(keys.owner, "owner");
  const agent = needKey(keys.agent, "agent");
  const villain = needKey(keys.villain, "villain");
  const client = new GuardClient(connection, opts.programId, agent.publicKey);
  const amount = opts.amount ?? BAD_AMOUNT;
  const before = await policy(connection, opts.programId, villain, amount);
  result.verdicts.push({
    label: "Aegis before",
    decision: before.decision,
    code: before.code,
  });
  result.facts = before.lanes.inspection.facts
    .filter((f) => f.id === "DELEGATED_DESTINATION")
    .map((f) => ({ id: f.id, level: f.level, detail: f.detail }));
  const initial = await client.assess(villain, amount);
  result.verdicts.push({
    label: "guard before",
    decision: initial.verdict,
    code: initial.code,
  });
  const bridge = await recordVerdictOnChain(client, owner, before);
  result.details.alreadyBlocked =
    !bridge.changed && /already recorded/.test(bridge.message);
  result.details.bridgeChanged = bridge.changed;
  if (bridge.signature)
    result.transactions.push({
      label: "deny entry",
      signature: bridge.signature,
      outcome: "succeeded",
    });
  const after = await policy(connection, opts.programId, villain, amount);
  const final = await client.assess(villain, amount);
  result.verdicts.push({
    label: "Aegis after",
    decision: after.decision,
    code: after.code,
  });
  result.verdicts.push({
    label: "guard after",
    decision: final.verdict,
    code: final.code,
  });
  const again = await recordVerdictOnChain(client, owner, after);
  result.details.rerunNoWrite =
    !again.changed && /already recorded/.test(again.message);
  result.notes.push(
    "The off-chain check sees a delegate before payment; guarded_pay checks again during the payment. A delegate added afterward can still sweep the received USDC."
  );
  result.ok =
    result.facts.length > 0 &&
    before.decision === "BLOCK" &&
    (initial.code === REFUSAL.DELEGATED_DESTINATION ||
      initial.code === REFUSAL.DENYLISTED) &&
    final.code === REFUSAL.DENYLISTED &&
    after.code === REFUSAL.DENYLISTED &&
    result.details.rerunNoWrite === true &&
    (bridge.changed || result.details.alreadyBlocked === true);
  return result;
}

/** The wrapper refuses a look-alike mint before the float wallet signs. */
export async function badMintX402(
  connection: Connection,
  keys: DemoKeys,
  opts: DemoOptions
): Promise<DemoResult> {
  const result = demoResult("bad-mint");
  const agent = needKey(keys.agent, "agent");
  const reporter = needKey(keys.reporter, "reporter");
  const float = needKey(keys.float, "float");
  const merchantKey = needKey(keys.merchant, "merchant");
  const badMint = needKey(keys.badMint, "look-alike mint");
  const client = new GuardClient(connection, opts.programId, agent.publicKey);
  const refill = await ensureFloat(client, agent, float.publicKey, {
    target: opts.floatTarget ?? GOOD_AMOUNT,
    min: (opts.floatTarget ?? GOOD_AMOUNT) / 2n,
  });
  if (refill.pay) notePay(result, "guarded float refill", refill.pay);
  result.details.floatSol = BigInt(
    await connection.getBalance(float.publicKey, "confirmed")
  );
  result.details.floatFunded = refill.funded;
  const network = caip2(await connection.getGenesisHash());
  let produced = 0;
  const merchant = createMerchant({
    connection,
    feePayer: merchantKey,
    network,
    services: [
      {
        route: "/lookalike",
        name: "Look-alike USDC",
        payTo: merchantKey.publicKey,
        demand: X402_PRICE,
        asset: badMint,
        product: () => ({ delivered: ++produced }),
      },
    ],
  });
  await new Promise<void>((resolve, reject) => {
    merchant.once("error", reject);
    merchant.listen(0, "127.0.0.1", resolve);
  });
  const merchantOrigin = `http://127.0.0.1:${(merchant.address() as AddressInfo).port}`;
  const audit = createAuditLogger({ client, reporter });
  let refusal: AegisPaymentRefused | null = null;
  try {
    const rpc = connectionRpc(connection);
    const signer = createAegisSigner(float, {
      rpc,
      network,
      usdc: USDC_MINT,
      onRefuse: audit.onRefuse,
      check: (payTo, amount, destination) =>
        aegisCheck(payTo, formatUnits(amount), {
          reader: rpc.reader,
          guard: opts.programId,
          destination,
          reasoner: null,
          recentDeploySlots: 0,
        }),
    });
    const fetcher = createAegisX402Fetch({
      signer,
      rpc,
      network,
      usdc: USDC_MINT,
      catalog: createCatalog([
        {
          payTo: merchantKey.publicKey.toBase58(),
          origin: merchantOrigin,
          name: "Look-alike demo",
          maxPrice: X402_PRICE,
        },
      ]),
      onRefuse: audit.onRefuse,
    });
    try {
      await fetcher(`${merchantOrigin}/lookalike`);
    } catch (err) {
      if (!(err instanceof AegisPaymentRefused)) throw err;
      refusal = err;
    }
  } finally {
    await new Promise<void>((resolve) => merchant.close(() => resolve()));
  }
  const receipts = await audit.flush();
  if (refusal) {
    result.verdicts.push({
      label: "x402",
      decision: refusal.verdict,
      code: refusal.code,
    });
    result.facts =
      refusal.offeredAsset?.facts.map((f) => ({
        id: f.id,
        level: f.level,
        detail: f.detail,
      })) ?? [];
  }
  for (const entry of receipts.entries)
    if (entry.signature)
      result.transactions.push({
        label: "refusal receipt",
        signature: entry.signature,
        outcome: "succeeded",
      });
  result.details.receiptCount = BigInt(receipts.logged);
  result.details.productCalls = BigInt(produced);
  result.ok =
    refill.balance + refill.funded >= (opts.floatTarget ?? GOOD_AMOUNT) / 2n &&
    result.details.floatSol === 0n &&
    refusal?.code === REFUSAL.NO_PAYABLE_OPTION &&
    receipts.logged === 1 &&
    receipts.failed === 0 &&
    produced === 0 &&
    result.facts.some((f) => f.id === "PERMANENT_DELEGATE") &&
    result.facts.some((f) => f.id === "FREEZE_AUTHORITY");
  return result;
}

/** An agent can skip the TS wrapper, but cannot bypass guarded_pay. */
export async function injectedDrain(
  connection: Connection,
  keys: DemoKeys,
  opts: DemoOptions
): Promise<DemoResult> {
  const result = demoResult("drain");
  const agent = needKey(keys.agent, "agent");
  const villain = needKey(keys.villain, "villain");
  const client = new GuardClient(connection, opts.programId, agent.publicKey);
  const cfg = await client.config();
  if (!cfg)
    throw new Error("the guard is not initialized; run yarn demo:setup");
  if (!(await client.entry("deny", villain)).member) {
    result.notes.push(
      "The villain is not denylisted; run the delegated beat first."
    );
    return result;
  }
  result.balances.vaultBefore = await usdcBalance(connection, cfg.vault);
  const pay = await client.guardedPay(
    agent,
    villain,
    opts.amount ?? BAD_AMOUNT,
    { skipPreflight: true }
  );
  notePay(result, "injected guarded_pay", pay);
  result.verdicts.push({
    label: "guarded_pay",
    decision: pay.ok ? "PAY" : "BLOCK",
    code: pay.code,
  });
  result.balances.vaultAfter = await usdcBalance(connection, cfg.vault);
  result.ok =
    !pay.ok &&
    pay.landed === true &&
    pay.code === REFUSAL.DENYLISTED &&
    result.balances.vaultAfter === result.balances.vaultBefore;
  result.notes.push(
    "The agent skipped Aegis, but the guard rejected the transaction on-chain."
  );
  return result;
}

/** Remove the agent, show NotAgent on-chain, and restore even if the beat fails. */
export async function killSwitch(
  connection: Connection,
  keys: DemoKeys,
  opts: DemoOptions
): Promise<DemoResult> {
  const result = demoResult("kill");
  const owner = needKey(keys.owner, "owner");
  const agent = needKey(keys.agent, "agent");
  const recipient = needKey(keys.good, "good recipient");
  const client = new GuardClient(connection, opts.programId, agent.publicKey);
  if (!(await client.entry("agent", agent.publicKey)).member)
    throw new Error(
      "the agent entry is missing before the kill switch; run yarn demo:setup"
    );
  const cfg = await client.config();
  if (!cfg)
    throw new Error("the guard is not initialized; run yarn demo:setup");
  result.balances.vaultBefore = await usdcBalance(connection, cfg.vault);
  try {
    const removed = await client.removeEntry(owner, "agent", agent.publicKey);
    notePay(result, "revoke agent", removed);
    if (removed.ok && !(await client.entry("agent", agent.publicKey)).member) {
      const clean = await policy(
        connection,
        opts.programId,
        recipient,
        opts.amount ?? GOOD_AMOUNT
      );
      result.verdicts.push({
        label: "Aegis still sees a clean recipient",
        decision: clean.decision,
        code: clean.code,
      });
      const pay = await client.guardedPay(
        agent,
        recipient,
        opts.amount ?? GOOD_AMOUNT,
        { skipPreflight: true }
      );
      notePay(result, "revoked agent payment", pay);
      result.verdicts.push({
        label: "guarded_pay",
        decision: pay.ok ? "PAY" : "BLOCK",
        code: pay.code,
      });
      result.details.refusedOnChain =
        !pay.ok && pay.landed === true && pay.code === REFUSAL.NOT_AN_AGENT;
    }
  } finally {
    try {
      const restored = await restoreAgentEntry(client, owner, agent.publicKey);
      if (restored.outcome) notePay(result, "restore agent", restored.outcome);
      result.details.restored = true;
    } catch (err) {
      result.details.restored = false;
      throw new Error(`the agent entry could not be restored; run yarn demo:restore-agent after the RPC recovers: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  result.balances.vaultAfter = await usdcBalance(connection, cfg.vault);
  result.ok =
    result.details.refusedOnChain === true &&
    result.details.restored === true &&
    result.balances.vaultAfter === result.balances.vaultBefore;
  return result;
}

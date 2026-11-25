// The five demo beats on the validator. The guard was initialized by
// aegis_guard.ts; every recipient and villain here is fresh for this suite.
import { Keypair } from "@solana/web3.js";
import { expect } from "chai";

import {
  badMintX402,
  delegatedRecipient,
  goodRecipient,
  injectedDrain,
  killSwitch,
} from "../src/demo/beats";
import { DemoKeys } from "../src/demo/common";
import { DemoSetupKeys, ensureDemoSetup } from "../src/demo/setup";
import { GuardClient } from "../src/guard/client";
import { Guard, loadKeypair, setup, sharedKeys } from "./helpers";

describe("demo beats on a live validator", () => {
  let g: Guard;
  let client: GuardClient;
  let keys: DemoSetupKeys;
  let beatKeys: DemoKeys;

  before(async () => {
    g = setup();
    const { owner, agent } = await sharedKeys(g);
    client = new GuardClient(g.connection, g.programId, agent.publicKey);
    expect(
      await client.config(),
      "run after aegis_guard.ts with mocha --sort"
    ).to.not.equal(null);
    keys = {
      owner,
      agent,
      payer: await g.fundedKeypair(10),
      reporter: await g.fundedKeypair(1),
      merchant: await g.fundedKeypair(2),
      good: Keypair.generate(),
      villain: Keypair.generate(),
      attacker: Keypair.generate(),
      float: Keypair.generate(),
      badMint: Keypair.generate(),
      mintAuthority: loadKeypair("tests/fixtures/mint-authority.json"),
    };
    beatKeys = {
      owner,
      agent,
      reporter: keys.reporter,
      merchant: keys.merchant,
      float: keys.float,
      good: keys.good.publicKey,
      villain: keys.villain.publicKey,
      badMint: keys.badMint.publicKey,
    };
  });

  after(async () => {
    if (client && keys)
      expect(
        (await client.entry("agent", keys.agent.publicKey)).member,
        "the kill switch restored the agent"
      ).to.equal(true);
  });

  it("setup creates the villain and entries once, then skips them on rerun", async () => {
    const first = await ensureDemoSetup(g.connection, keys, {
      programId: g.programId,
      localnet: true,
    });
    expect(first.ready).to.equal(true);
    expect(
      first.actions.some(
        (a) =>
          a.label === "create Token-2022 look-alike mint" && a.state === "done"
      )
    ).to.equal(true);
    const second = await ensureDemoSetup(g.connection, keys, {
      programId: g.programId,
      localnet: true,
    });
    expect(second.ready).to.equal(true);
    expect(
      second.actions.every((a) => a.state === "skipped"),
      JSON.stringify(second.actions)
    ).to.equal(true);
    expect(await g.connection.getBalance(keys.float.publicKey)).to.equal(0);
  });

  it("good: Aegis says PAY and guarded_pay moves exactly one USDC", async () => {
    const out = await goodRecipient(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect(out.ok).to.equal(true);
    expect(out.verdicts.map((v) => v.decision)).to.deep.equal(["PAY", "PAY"]);
    expect(out.transactions).to.have.length(1);
    expect(out.balances.vaultBefore - out.balances.vaultAfter).to.equal(
      1_000_000n
    );
  });

  it("delegated: the delegate is HIGH, then the bridge writes deny and reruns without a write", async () => {
    const first = await delegatedRecipient(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect(first.ok).to.equal(true);
    expect(
      first.facts.find((f) => f.id === "DELEGATED_DESTINATION")?.level
    ).to.equal("HIGH");
    expect(first.verdicts.map((v) => [v.decision, v.code])).to.deep.equal([
      ["BLOCK", "HIGH_RISK_ACCOUNT"],
      ["REVIEW", "DELEGATED_DESTINATION"],
      ["BLOCK", "DENYLISTED"],
      ["BLOCK", "DENYLISTED"],
    ]);
    expect([
      first.details.bridgeChanged,
      first.details.rerunNoWrite,
      first.transactions.length,
    ]).to.deep.equal([true, true, 1]);
    const second = await delegatedRecipient(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect([
      second.ok,
      second.details.alreadyBlocked,
      second.transactions.length,
    ]).to.deep.equal([true, true, 0]);
  });

  it("bad mint: x402 refuses the look-alike, logs a receipt, and the float has no SOL", async () => {
    const out = await badMintX402(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect(out.ok).to.equal(true);
    expect(out.verdicts.map((v) => v.code)).to.deep.equal([
      "NO_PAYABLE_OPTION",
    ]);
    expect(out.facts.map((f) => f.id)).to.include.members([
      "NOT_PINNED_ASSET",
      "PERMANENT_DELEGATE",
      "SPOOFED_METADATA",
      "FREEZE_AUTHORITY",
    ]);
    expect([
      out.details.floatSol,
      out.details.receiptCount,
      out.details.productCalls,
    ]).to.deep.equal([0n, 1n, 0n]);
    expect(
      out.transactions.some(
        (t) => t.label === "guarded float refill" && t.outcome === "succeeded"
      )
    ).to.equal(true);
    expect(
      out.transactions.some(
        (t) => t.label === "refusal receipt" && t.outcome === "succeeded"
      )
    ).to.equal(true);
  });

  it("drain: a direct guarded_pay lands failed and leaves the vault unchanged", async () => {
    const out = await injectedDrain(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect(out.ok).to.equal(true);
    expect(out.verdicts[0].code).to.equal("DENYLISTED");
    expect(out.transactions[0].outcome).to.equal("failed");
    expect(out.balances.vaultAfter).to.equal(out.balances.vaultBefore);
  });

  it("kill switch: NotAgent lands failed, then the agent entry is restored", async () => {
    const out = await killSwitch(g.connection, beatKeys, {
      programId: g.programId,
    });
    expect(out.ok).to.equal(true);
    expect(out.verdicts.map((v) => v.code)).to.deep.equal([
      null,
      "NOT_AN_AGENT",
    ]);
    expect(out.transactions.map((t) => t.outcome)).to.deep.equal([
      "succeeded",
      "failed",
      "succeeded",
    ]);
    expect(out.details.restored).to.equal(true);
    expect((await client.entry("agent", keys.agent.publicKey)).member).to.equal(
      true
    );
  });
});

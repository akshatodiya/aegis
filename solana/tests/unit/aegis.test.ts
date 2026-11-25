// The decision engine's order, with real lanes over a fake chain and a stub LLM.
import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";

import { aegisCheck, formatVerdict } from "../../src/aegis";
import { checkReputation } from "../../src/lanes/reputation";
import type { LlmInput, LlmResult, Reasoner } from "../../src/reasoning";
import { associatedTokenAddress } from "../../src/guard/layout";
import { FakeChain, TOKEN_PROGRAM, USDC_MINT, key, offCurve, putGuard, putV3Program, putWallet, tokenAccountBytes } from "./fixtures";

function stubLlm(result: Partial<LlmResult> = {}) {
  const calls: LlmInput[] = [];
  const reasoner: Reasoner = async (input) => {
    calls.push(input);
    return { available: true, summary: "It is a vault controlled by a program.", risk: "medium", ...result };
  };
  return { reasoner, calls };
}

describe("unit: aegisCheck", () => {
  let chain: FakeChain;
  let guard: ReturnType<typeof putGuard>;
  beforeEach(() => {
    chain = new FakeChain();
    guard = putGuard(chain);
  });
  const check = (r: PublicKey, amount: string | number, reasoner: Reasoner | null = null, extra = {}) =>
    aegisCheck(r, amount, { reader: chain, guard: guard.programId, reasoner, ...extra });

  it("a clean wallet and a small amount PAY, with no code and no LLM call", async () => {
    const { wallet } = putWallet(chain);
    const llm = stubLlm();
    const r = await check(wallet, "10", llm.reasoner);
    expect([r.decision, r.code]).to.deep.equal(["PAY", null]);
    expect(llm.calls).to.have.length(0);
    expect(r.amountUnits).to.equal(10_000_000n);
    expect(r.reasons[0]).to.match(/^Inspection: /);
  });

  it("the guard's own deny list BLOCKs off-chain too, before anything else", async () => {
    const { wallet } = putWallet(chain, { ata: { state: 2 } }); // also frozen (HIGH)
    guard.add("deny", wallet);
    const r = await check(wallet, "1");
    expect([r.decision, r.code]).to.deep.equal(["BLOCK", "DENYLISTED"]);
    expect(r.reasons[0]).to.match(/Denylisted on-chain/);
  });

  it("HIGH BLOCKs without asking the LLM, and nothing downgrades it", async () => {
    const { wallet } = putWallet(chain, { ata: { delegate: key(), delegatedAmount: 10n ** 12n } });
    const llm = stubLlm({ risk: "low", summary: "looks fine" });
    const r = await check(wallet, "1", llm.reasoner);
    expect([r.decision, r.code]).to.deep.equal(["BLOCK", "HIGH_RISK_ACCOUNT"]);
    expect(llm.calls, "analyze-only: HIGH never reaches the LLM").to.have.length(0);
    expect(r.llm).to.equal(null);
  });

  it("an unreadable chain is ASK_HUMAN / LANE_UNAVAILABLE, never PAY", async () => {
    const { wallet } = putWallet(chain);
    chain.failing = true;
    const r = await check(wallet, "1");
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "LANE_UNAVAILABLE"]);
  });

  it("MEDIUM is ASK_HUMAN, and the LLM explains it with the lane's typed facts", async () => {
    const pda = offCurve();
    const llm = stubLlm();
    const r = await check(pda, "1", llm.reasoner);
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "MEDIUM_RISK_ACCOUNT"]);
    expect(llm.calls).to.have.length(1);
    expect(llm.calls[0].facts.map((f) => f.id)).to.include("UNKNOWN_CONTROLLER");
    expect(r.reasons.join("\n")).to.match(/LLM summary \(model output, risk medium\)/);
  });

  it("an LLM that is down still escalates, on deterministic grounds", async () => {
    const pda = offCurve();
    const llm = stubLlm({ available: false, summary: null, risk: null, error: "claude: command not found" });
    const r = await check(pda, "1", llm.reasoner);
    expect(r.decision).to.equal("ASK_HUMAN");
    expect(r.reasons.join("\n")).to.match(/LLM unavailable: claude: command not found - escalating on deterministic grounds/);
  });

  it("a large first payment is ASK_HUMAN / UNUSUAL_AMOUNT", async () => {
    const { wallet } = putWallet(chain);
    const r = await check(wallet, "60", stubLlm().reasoner);
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "UNUSUAL_AMOUNT"]);
    expect(r.reasons[0]).to.match(/^Behavior: /);
  });

  it("the same payment is PAY once the history covers it", async () => {
    const { wallet } = putWallet(chain);
    guard.paid(wallet, 2n, 20_000_000n, 30_000_000n);
    expect((await check(wallet, "60")).decision).to.equal("PAY");
    expect((await check(wallet, "101")).code).to.equal("UNUSUAL_AMOUNT");
  });

  it("an immutable-program vault that the owner allowlisted is PAY", async () => {
    const program = key();
    putV3Program(chain, program, { authority: null });
    const pda = offCurve("vault", program);
    guard.add("allow", pda, program);
    chain.set(associatedTokenAddress(pda, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: pda }));
    const r = await check(pda, "5");
    expect(r.decision).to.equal("PAY");
  });

  it("an account that names itself as its owner BLOCKs; it is not a program", async () => {
    const x = offCurve("self");
    chain.set(x, x, Buffer.alloc(8));
    chain.set(associatedTokenAddress(x, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: x }));
    expect((await check(x, "5")).decision).to.equal("BLOCK");
  });

  it("a large payment whose history can't be read is LANE_UNAVAILABLE, not UNUSUAL_AMOUNT", async () => {
    const { wallet } = putWallet(chain);
    guard.paid(wallet, 10n, 1_000_000_000n, 2_000_000_000n);
    const stats = guard.pdas.stats(wallet);
    const reader = {
      getAccounts: async (keys: PublicKey[], slice?: any) => {
        if (keys.some((k) => k.equals(stats))) throw new Error("429 Too Many Requests");
        return chain.getAccounts(keys, slice);
      },
      getSlot: () => chain.getSlot(),
    };
    const r = await check(wallet, "60", null, { reader });
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "LANE_UNAVAILABLE"]);
    expect(r.reasons.join("\n")).to.match(/could not be read/);
  });

  it("with guard: null the verdict says the lists and history were not consulted", async () => {
    const { wallet } = putWallet(chain);
    guard.add("deny", wallet);
    const r = await aegisCheck(wallet, "1", { reader: chain, guard: null, reasoner: null });
    expect(r.decision).to.equal("PAY");
    expect(r.reasons.join("\n")).to.match(/No guard configured: its deny\/allow lists and payment history were not consulted/);
  });

  it("rejects an amount that is zero, negative, over-precise or not a number", async () => {
    const { wallet } = putWallet(chain);
    for (const bad of ["-1", "1.0000001", "abc", "", "0", "0.000000"]) {
      let threw = false;
      try {
        await check(wallet, bad);
      } catch {
        threw = true;
      }
      expect(threw, bad).to.equal(true);
    }
  });

  it("formats a verdict with the code beside the banner", async () => {
    const { wallet } = putWallet(chain, { ata: { state: 2 } });
    const text = formatVerdict(await check(wallet, "1"));
    expect(text).to.match(/BLOCK.*HIGH_RISK_ACCOUNT/);
    expect(text).to.match(/frozen/);
  });

  describe("reputation lane", () => {
    it("is a mock with empty lists, compared exactly (base58 has no case)", () => {
      const r = checkReputation(key().toBase58());
      expect(r.listed).to.equal(null);
      expect(r.reason).to.match(/mock lane/);
    });

    it("reports an on-chain deny as a deny", () => {
      const r = checkReputation(key().toBase58(), { denied: true, allow: null });
      expect([r.listed, r.level]).to.deep.equal(["deny", "HIGH"]);
    });
  });
});

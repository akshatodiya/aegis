// The pieces around the x402 hooks: the catalog, the float plans, and the
// audit logger. Ported from the EVM build's float and audit tests.
import { expect } from "chai";
import { Keypair, PublicKey } from "@solana/web3.js";

import { MAX_REASON_BYTES, createAuditLogger, refusalEntry, trimReason } from "../../src/audit";
import { ensureFloat, floatPlan, gasFloatPlan } from "../../src/float";
import { TOKEN_PROGRAM, USDC_MINT } from "../../src/config";
import { GuardClient } from "../../src/guard/client";
import { associatedTokenAddress } from "../../src/guard/layout";
import { REFUSAL } from "../../src/refusals";
import { toBaseUnits } from "../../src/units";
import { canonicalAddress, canonicalOrigin, createCatalog } from "../../src/x402/catalog";
import { AegisPaymentRefused } from "../../src/x402/refused";
import { FakeChain, key, tokenAccountBytes } from "./fixtures";

const usd = (n: number) => toBaseUnits(n);
const refusal = (o: Partial<{ reason: string; code: string; recipient: string | null; amount: bigint | null; verdict: "BLOCK" | "ASK_HUMAN" }> = {}) =>
  new AegisPaymentRefused(o.reason ?? "recipient denylisted", o.verdict ?? "BLOCK", { code: (o.code ?? REFUSAL.DENYLISTED) as any, recipient: o.recipient, amount: o.amount });

describe("unit: x402 support", () => {
  describe("catalog", () => {
    it("looks up base58 addresses exactly: no case folding, no lookalike forms", () => {
      const a = key().toBase58();
      const c = createCatalog([{ payTo: a, origin: "https://merchant.test", name: "Weather", maxPrice: 100_000n }]);
      expect(c.lookup(a)).to.deep.equal({ payTo: a, origin: "https://merchant.test", name: "Weather", maxPrice: 100_000n });
      expect(c.lookup(a.toLowerCase())).to.equal(null);
      expect(c.lookup(new PublicKey(a) as any)).to.equal(null);
      expect(c.lookup(undefined)).to.equal(null);
    });

    it("refuses to be built from an invalid address or a non-positive price", () => {
      expect(() => createCatalog([{ payTo: "not-an-address", origin: "https://merchant.test", maxPrice: 1n }])).to.throw(/no valid payTo/);
      expect(() => createCatalog([{ payTo: key().toBase58(), origin: "https://merchant.test", maxPrice: 0n }])).to.throw(/positive maxPrice/);
      expect(() => createCatalog([{ payTo: key().toBase58(), origin: "https://merchant.test/path", maxPrice: 1n }])).to.throw(/canonical HTTP origin/);
      const a = key().toBase58();
      expect(() => createCatalog([{ payTo: a, origin: "https://merchant.test", maxPrice: 1n }, { payTo: a, origin: "https://stranger.test", maxPrice: 1n }])).to.throw(/duplicated/);
      expect(canonicalOrigin("https://merchant.test/")).to.equal(null);
      expect(canonicalOrigin("ftp://merchant.test")).to.equal(null);
      expect(canonicalAddress(key().toBase58())).to.be.a("string");
      expect(canonicalAddress([1, 2, 3])).to.equal(null);
      expect(canonicalAddress("1".repeat(44))).to.equal(null);
    });
  });

  describe("float plans", () => {
    it("no top-up at or above min; below it, back up to target (not just to min)", () => {
      expect(floatPlan({ balance: usd(5), target: usd(5), min: usd(2) })).to.deep.equal({ topUp: false, amount: 0n });
      expect(floatPlan({ balance: usd(2), target: usd(5), min: usd(2) })).to.deep.equal({ topUp: false, amount: 0n });
      expect(floatPlan({ balance: usd(1), target: usd(5), min: usd(2) })).to.deep.equal({ topUp: true, amount: usd(4) });
    });

    it("an empty float asks for the whole target; min == target refills any shortfall", () => {
      expect(floatPlan({ balance: 0n, target: usd(5), min: usd(2) })).to.deep.equal({ topUp: true, amount: usd(5) });
      expect(floatPlan({ balance: usd(3), target: usd(5), min: usd(5) })).to.deep.equal({ topUp: true, amount: usd(2) });
    });

    it("a min above target is a misconfiguration, not a silent pass", () => {
      expect(() => floatPlan({ balance: 0n, target: usd(2), min: usd(5) })).to.throw(/cannot exceed target/);
      expect(() => gasFloatPlan({ balance: 0n, target: 1n, min: 2n })).to.throw(/cannot exceed target/);
    });

    it("the agent's SOL: same refill rule, and a surplus is reported as exposure", () => {
      const sol = 1_000_000_000n;
      expect(gasFloatPlan({ balance: sol / 20n, target: sol / 20n, min: sol / 50n })).to.deep.equal({ topUp: false, amount: 0n, exposure: 0n });
      expect(gasFloatPlan({ balance: sol / 100n, target: sol / 20n, min: sol / 50n })).to.deep.equal({ topUp: true, amount: sol / 20n - sol / 100n, exposure: 0n });
      expect(gasFloatPlan({ balance: 5n * sol, target: sol / 20n, min: sol / 50n }).exposure).to.equal(5n * sol - sol / 20n);
    });

    it("refuses to count a reassigned, wrong-mint or frozen float account", async () => {
      const wallet = key();
      const chain = new FakeChain();
      const ata = associatedTokenAddress(wallet, USDC_MINT);
      const client = {
        programId: key(),
        reader: chain,
        config: async () => ({ mint: USDC_MINT, dailyLimit: usd(5) }),
        ensureRecipientAta: async () => { throw new Error("unexpected account creation"); },
        guardedPay: async () => { throw new Error("unexpected payment"); },
      } as unknown as GuardClient;
      const agent = Keypair.generate();
      const check = async (data: Buffer, reason: RegExp) => {
        chain.set(ata, TOKEN_PROGRAM, data);
        try {
          await ensureFloat(client, agent, wallet, { target: usd(1), min: usd(0.5) });
          throw new Error("expected an invalid float account");
        } catch (err) {
          expect((err as Error).message).to.match(reason);
        }
      };
      await check(tokenAccountBytes({ owner: key(), amount: usd(1) }), /reassigned/);
      await check(tokenAccountBytes({ owner: wallet, mint: key(), amount: usd(1) }), /another mint/);
      await check(tokenAccountBytes({ owner: wallet, amount: usd(1), state: 2 }), /frozen/);
    });
  });

  describe("audit logger", () => {
    describe("trimReason", () => {
      it("keeps short reasons, collapses whitespace, and names an empty one", () => {
        expect(trimReason("recipient denylisted")).to.equal("recipient denylisted");
        expect(trimReason("  a\n\n b\t c ")).to.equal("a b c");
        expect(trimReason("")).to.equal("refused (no reason recorded)");
        expect(trimReason(null)).to.equal("refused (no reason recorded)");
      });

      it("caps at 256 bytes, measured as UTF-8, without splitting a character", () => {
        const long = trimReason("x".repeat(1000));
        expect(Buffer.byteLength(long)).to.be.at.most(MAX_REASON_BYTES);
        expect(long.endsWith("...")).to.equal(true);
        const wide = trimReason("€".repeat(200)); // 3 bytes each
        expect(Buffer.byteLength(wide)).to.be.at.most(MAX_REASON_BYTES);
        expect(wide).to.not.include("�");
      });
    });

    describe("refusalEntry", () => {
      it("carries recipient, amount, verdict, code and reason", () => {
        const who = key().toBase58();
        const e = refusalEntry(refusal({ recipient: who, amount: 5_000_000n, verdict: "ASK_HUMAN", code: REFUSAL.UNUSUAL_AMOUNT, reason: "large" }));
        expect([e.recipient!.toBase58(), e.amount, e.verdict, e.code, e.reason]).to.deep.equal([who, 5_000_000n, "ASK_HUMAN", "UNUSUAL_AMOUNT", "large"]);
      });

      it("a missing or invalid recipient is None, not an invented address", () => {
        expect(refusalEntry(refusal({ recipient: null })).recipient).to.equal(null);
        expect(refusalEntry(refusal({ recipient: "0xdeadbeef" })).recipient).to.equal(null);
        expect(refusalEntry(refusal({ recipient: "l" + key().toBase58().slice(1) })).recipient, "l is not base58").to.equal(null);
      });

      it("an amount outside u64, negative or junk is recorded as 0", () => {
        expect(refusalEntry(refusal({ amount: 1n << 64n })).amount).to.equal(0n);
        expect(refusalEntry(refusal({ amount: -1n })).amount).to.equal(0n);
        expect(refusalEntry({ amount: "lots" as any, reason: "x" }).amount).to.equal(0n);
      });

      it("only ASK_HUMAN is not BLOCK, and a code we don't know is UNKNOWN", () => {
        expect(refusalEntry({ verdict: "PAY" as any, reason: "x" }).verdict).to.equal("BLOCK");
        expect(refusalEntry({ code: "MADE_UP" as any, reason: "x" }).code).to.equal(REFUSAL.UNKNOWN);
      });

      it("the code has its own field: a long reason can't push it out, and the reason never carries it", () => {
        const e = refusalEntry(refusal({ code: REFUSAL.OVER_POSTED_PRICE, reason: "bait ".repeat(200) }));
        expect(e.code).to.equal("OVER_POSTED_PRICE");
        expect(e.reason.startsWith("OVER_POSTED_PRICE")).to.equal(false);
      });
    });

    describe("createAuditLogger", () => {
      const recorder = (fail = false) => {
        const sent: string[] = [];
        let n = 0;
        return {
          sent,
          send: async (e: { code: string }) => {
            sent.push(e.code);
            if (fail) throw new Error("NotReporter");
            return `sig${++n}`;
          },
        };
      };

      it("is disabled with neither a writer nor a client+reporter", () => {
        const a = createAuditLogger();
        expect(a.enabled).to.equal(false);
        a.onRefuse(refusal());
        expect(a.entries).to.have.length(0);
      });

      it("one refusal through both hooks is one entry; two with the same text are two", async () => {
        const r = recorder();
        const a = createAuditLogger({ send: r.send });
        const one = refusal();
        a.onRefuse(one);
        a.onRefuse(one);
        a.onRefuse(refusal());
        const out = await a.flush();
        expect([out.logged, r.sent.length]).to.deep.equal([2, 2]);
      });

      it("onRefuse returns before the write lands", async () => {
        let release!: () => void;
        const gate = new Promise<void>((r) => (release = r));
        const a = createAuditLogger({
          send: async () => {
            await gate;
            return "sig";
          },
        });
        a.onRefuse(refusal());
        expect(a.entries[0].signature).to.equal(undefined);
        release();
        await a.flush();
        expect(a.entries[0].signature).to.equal("sig");
      });

      it("a failed write is recorded, never thrown", async () => {
        const r = recorder(true);
        const a = createAuditLogger({ send: r.send });
        a.onRefuse(refusal());
        const out = await a.flush();
        expect([out.failed, out.logged]).to.deep.equal([1, 0]);
        expect(a.entries[0].error).to.equal("NotReporter");
      });

      it("a throwing printer does not change a receipt or stop the next write", async () => {
        let sent = 0;
        const a = createAuditLogger({ send: async () => `sig${++sent}`, log: () => { throw new Error("printer failed"); } });
        a.onRefuse(refusal());
        a.onRefuse(refusal());
        const out = await a.flush();
        expect([out.logged, out.failed, sent]).to.deep.equal([2, 0, 2]);
        expect(a.entries.map((e) => e.signature)).to.deep.equal(["sig1", "sig2"]);
        expect(a.entries.map((e) => e.error)).to.deep.equal([undefined, undefined]);
      });

      it("past the cap, refusals continue and receipts stop, said once", async () => {
        const r = recorder();
        const lines: string[] = [];
        const a = createAuditLogger({ send: r.send, maxWrites: 2, log: (l) => lines.push(l) });
        for (let i = 0; i < 5; i++) a.onRefuse(refusal());
        const out = await a.flush();
        expect([out.logged, out.skipped, r.sent.length]).to.deep.equal([2, 3, 2]);
        expect(lines.filter((l) => /receipts stop/.test(l))).to.have.length(1);
      });

      it("writes go out one at a time, in order", async () => {
        const order: string[] = [];
        let inFlight = 0;
        const a = createAuditLogger({
          send: async (e) => {
            inFlight++;
            expect(inFlight).to.equal(1);
            await new Promise((r) => setTimeout(r, 2));
            order.push(e.code);
            inFlight--;
            return "s";
          },
        });
        for (const code of [REFUSAL.UNKNOWN_SERVICE, REFUSAL.OVER_POSTED_PRICE, REFUSAL.DENYLISTED]) a.onRefuse(refusal({ code }));
        await a.flush();
        expect(order).to.deep.equal(["UNKNOWN_SERVICE", "OVER_POSTED_PRICE", "DENYLISTED"]);
      });

      it("never throws into the refusal path, even for junk", () => {
        const a = createAuditLogger({ send: async () => "s" });
        expect(() => a.onRefuse(null as any)).to.not.throw();
        expect(() => a.onRefuse("x" as any)).to.not.throw();
      });
    });
  });
});

void Keypair;

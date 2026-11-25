// Ported from the EVM build's behavior tests. The decision is pure; only the
// history source changed (a stats account instead of a log window).
//
// What they guard: "never paid", "paid before" and "could not find out" are
// three different answers; and "paid before" is a claim about size as well as
// count, because a count alone can be bought with one dust payment.
import { expect } from "chai";

import { behaviorVerdict, timesPaid } from "../../src/lanes/behavior";
import { SYSTEM_PROGRAM } from "../../src/config";
import { toBaseUnits } from "../../src/units";
import { FakeChain, key, putGuard, statsBytes } from "./fixtures";

const NEVER = { count: 0, largest: 0n };
const UNKNOWN = null;
const usd = (n: number | string) => toBaseUnits(n);
const paid = (count: number, largest: number) => ({ count, largest: usd(largest) });

describe("unit: behavior lane", () => {
  it("a large payment to an unseen recipient escalates", () => {
    const v = behaviorVerdict(usd(60), NEVER);
    expect(v.level).to.equal("MEDIUM");
    expect(v.escalate).to.equal(true);
    expect(v.reason).to.match(/has not paid before/);
  });

  it("a large payment in line with what we have paid before does not escalate", () => {
    const v = behaviorVerdict(usd(60), paid(3, 200));
    expect([v.level, v.escalate]).to.deep.equal(["LOW", false]);
    expect(v.reason).to.match(/paid 3 times before, up to 200 USDC/);
  });

  it("an unreadable history escalates a large payment, and says so honestly", () => {
    const v = behaviorVerdict(usd(60), UNKNOWN);
    expect(v.escalate).to.equal(true);
    expect(v.reason).to.match(/could not be read/);
    expect(v.reason).to.not.match(/never/);
  });

  it("a small payment stays LOW whatever the history says", () => {
    for (const history of [NEVER, paid(1, 1), UNKNOWN]) {
      const v = behaviorVerdict(usd(5), history);
      expect([v.level, v.escalate]).to.deep.equal(["LOW", false]);
    }
  });

  it("the threshold is exclusive - exactly at the limit is not large", () => {
    expect(behaviorVerdict(usd(50), NEVER).escalate).to.equal(false);
    expect(behaviorVerdict(usd(51), NEVER).escalate).to.equal(true);
  });

  it("singular and plural read correctly", () => {
    expect(behaviorVerdict(usd(5), paid(1, 1)).reason).to.match(/paid 1 time before/);
    expect(behaviorVerdict(usd(5), paid(2, 1)).reason).to.match(/paid 2 times before/);
  });

  it("a dust payment does not launder a huge one to the same address", () => {
    expect(behaviorVerdict(usd(1), NEVER).escalate, "the dust payment itself still passes").to.equal(false);
    const v = behaviorVerdict(usd(500), paid(1, 1));
    expect(v.escalate).to.equal(true);
    expect(v.reason).to.match(/largest the guard has paid this recipient before \(1 USDC/);
  });

  it("familiarity is capped at a multiple of what we actually paid them", () => {
    expect(behaviorVerdict(usd(500), paid(2, 100)).escalate, "exactly 5x still passes").to.equal(false);
    expect(behaviorVerdict(usd(501), paid(2, 100)).escalate, "one over 5x escalates").to.equal(true);
  });

  it("exactly 5x passes in base units too, where floats would round it over", () => {
    // 10.000001 * 5 is 50.000004999999994 in doubles
    const history = { count: 1, largest: 10_000_001n };
    expect(behaviorVerdict(50_000_005n, history).escalate, "exactly 5x").to.equal(false);
    expect(behaviorVerdict(50_000_006n, history).escalate, "one base unit over").to.equal(true);
  });

  it("an unknown history says why: unreadable, or no guard configured", () => {
    expect(behaviorVerdict(usd(60), UNKNOWN, "was not consulted (no guard configured)").reason).to.match(/no guard configured/);
  });

  it("a genuine relationship is not punished for growing", () => {
    expect(behaviorVerdict(usd(300), paid(4, 250)).escalate).to.equal(false);
    expect(behaviorVerdict(usd(900), paid(9, 800)).escalate).to.equal(false);
  });

  it("a big history does not excuse an unrelated jump", () => {
    expect(behaviorVerdict(usd(10_000), paid(40, 20)).escalate).to.equal(true);
  });

  describe("reading the stats account", () => {
    it("no stats account means never paid, reported as {0, 0}", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      expect(await timesPaid(chain, g.programId, key())).to.deep.equal({ count: 0, largest: 0n });
    });

    it("reads the largest payment in base units", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      const r = key();
      g.paid(r, 3n, 200_000_000n, 250_000_000n);
      expect(await timesPaid(chain, g.programId, r)).to.deep.equal({ count: 3, largest: 200_000_000n });
    });

    it("a dust payment is reported at its real size", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      const r = key();
      g.paid(r, 1n, 1n, 1n);
      expect(await timesPaid(chain, g.programId, r)).to.deep.equal({ count: 1, largest: 1n });
    });

    it("a failed read is null, never 'never'", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      chain.failing = true;
      expect(await timesPaid(chain, g.programId, key())).to.equal(null);
    });

    it("a guard-owned account with the wrong layout is null (unknown), not 'never'", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      const r = key();
      chain.set(g.pdas.stats(r), g.programId, Buffer.alloc(40));
      expect(await timesPaid(chain, g.programId, r)).to.equal(null);
    });

    it("lamports someone sent to the stats address are still 'never'", async () => {
      const chain = new FakeChain();
      const g = putGuard(chain);
      const r = key();
      chain.set(g.pdas.stats(r), SYSTEM_PROGRAM, statsBytes(9n, 9n, 9n));
      expect(await timesPaid(chain, g.programId, r)).to.deep.equal({ count: 0, largest: 0n });
    });

    it("no guard configured means the history is unknown", async () => {
      expect(await timesPaid(new FakeChain(), null, key())).to.equal(null);
    });
  });
});

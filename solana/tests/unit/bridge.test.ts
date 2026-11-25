// Which list a BLOCK is written to, and when an allowlist is offered. Both are
// computed from the lanes' state, never from an error string.
import { expect } from "chai";
import { Keypair, PublicKey } from "@solana/web3.js";

import { AegisResult, aegisCheck } from "../../src/aegis";
import { actOnVerdict, blockTarget, confirmOwner, isProtectedProgram, needsVetting, recordVerdictOnChain, vetThenPay } from "../../src/guard/bridge";
import type { GuardClient, OnchainAssessment, SendOutcome } from "../../src/guard/client";
import { associatedTokenAddress } from "../../src/guard/layout";
import { FakeChain, SYSTEM_PROGRAM, TOKEN_PROGRAM, USDC_MINT, key, offCurve, putGuard, putV3Program, putV4Program, putWallet, tokenAccountBytes } from "./fixtures";

const landed = (o: Partial<SendOutcome> = {}): SendOutcome => ({ ok: true, signature: "sig", landed: true, code: null, error: null, logs: [], ...o });
const assessment = (verdict: OnchainAssessment["verdict"], reason = "clear"): OnchainAssessment => ({ verdict, reason, code: null, spentToday: 0n, dailyLimit: 0n });

/** A GuardClient stand-in: scripted answers, and a record of what was sent. */
function fakeClient(o: {
  programId: PublicKey;
  assess?: () => Promise<OnchainAssessment>;
  addEntry?: SendOutcome;
  entryAfterWrite?: boolean;
  pay?: SendOutcome;
}) {
  const sent: string[] = [];
  const members = new Set<string>();
  const client = {
    programId: o.programId,
    assess: o.assess ?? (async () => assessment("PAY")),
    async entry(kind: string, k: PublicKey) {
      return { member: members.has(`${kind}:${k.toBase58()}`), controller: null };
    },
    async addEntry(_owner: Keypair, kind: string, k: PublicKey) {
      sent.push(`add ${kind}`);
      const out = o.addEntry ?? landed();
      if (out.landed !== false && o.entryAfterWrite !== false) members.add(`${kind}:${k.toBase58()}`);
      return out;
    },
    async guardedPay() {
      sent.push("pay");
      return o.pay ?? landed();
    },
  };
  return { client: client as unknown as GuardClient, sent };
}

describe("unit: bridge decisions", () => {
  let chain: FakeChain;
  let guard: ReturnType<typeof putGuard>;
  beforeEach(() => {
    chain = new FakeChain();
    guard = putGuard(chain);
  });
  const check = (r: PublicKey, amount = "1") => aegisCheck(r, amount, { reader: chain, guard: guard.programId, reasoner: null });

  describe("blockTarget", () => {
    it("only a BLOCK is ever written", async () => {
      const { wallet } = putWallet(chain);
      expect(blockTarget(await check(wallet), guard.programId).kind).to.equal("none");
    });

    it("a finding about a wallet's USDC account denylists the wallet", async () => {
      const { wallet } = putWallet(chain, { ata: { delegate: key(), delegatedAmount: 10n ** 12n } });
      const t = blockTarget(await check(wallet), guard.programId);
      expect(t.kind).to.equal("deny");
      expect((t as any).key.toBase58()).to.equal(wallet.toBase58());
    });

    it("a closed controlling program is blocked by program id", async () => {
      const retracted = key();
      putV4Program(chain, retracted, { status: 0, authority: key() });
      const a = key();
      chain.set(a, retracted, Buffer.alloc(8));
      const t = blockTarget(await check(a), guard.programId);
      expect(t.kind).to.equal("blockprog");
      expect((t as any).key.toBase58()).to.equal(retracted.toBase58());
    });

    it("never blocks a registry program or the guard itself; falls back to the address", async () => {
      expect(isProtectedProgram(TOKEN_PROGRAM, guard.programId)).to.equal(true);
      expect(isProtectedProgram(guard.programId, guard.programId)).to.equal(true);
      expect(isProtectedProgram(key(), guard.programId)).to.equal(false);
      // A recipient owned by a (fake) closed "program" that is in the registry
      const memo = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"); // not on the fake chain: reads as closed
      const a = key();
      chain.set(a, memo, Buffer.alloc(8));
      const r = await check(a);
      expect(r.decision).to.equal("BLOCK");
      const t = blockTarget(r, guard.programId);
      expect(t.kind).to.equal("deny");
    });

    it("a recipient type the guard already refuses needs no write", async () => {
      const m = key();
      chain.set(m, TOKEN_PROGRAM, Buffer.alloc(82));
      expect(blockTarget(await check(m), guard.programId).kind).to.equal("none");
    });

    it("a program-level block is written even when the recipient is already denylisted", async () => {
      const retracted = key();
      putV4Program(chain, retracted, { status: 0, authority: key() });
      const a = key();
      chain.set(a, retracted, Buffer.alloc(8));
      guard.add("deny", a);
      const r = await check(a);
      expect(r.code).to.equal("DENYLISTED");
      const t = blockTarget(r, guard.programId);
      expect(t.kind).to.equal("blockprog");
      expect((t as any).key.toBase58()).to.equal(retracted.toBase58());
    });

    it("lamports a stranger sends to a wallet's ATA address never get the wallet denylisted", async () => {
      const { wallet, ata } = putWallet(chain, { ata: null });
      chain.set(ata, SYSTEM_PROGRAM);
      const r = await check(wallet);
      expect(r.decision).to.equal("ASK_HUMAN");
      expect(blockTarget(r, guard.programId).kind).to.equal("none");
    });

    it("a denylisted-off-chain recipient is written to the on-chain deny list", async () => {
      const { wallet } = putWallet(chain);
      guard.add("deny", wallet);
      const t = blockTarget(await check(wallet), guard.programId);
      expect(t.kind).to.equal("deny");
    });
  });

  describe("needsVetting", () => {
    it("offers an allowlist for a clean program-owned keypair address, naming no program as controller", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(a, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: a }));
      const v = needsVetting((await check(a)).lanes.inspection);
      expect(v.offer).to.equal(true);
      expect(v.controller).to.equal(null);
    });

    it("offers nothing off the curve: the data owner is not proof of who signs", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const x = offCurve("x", key());
      chain.set(x, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(x, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: x }));
      const v = needsVetting((await check(x)).lanes.inspection);
      expect(v.offer).to.equal(false);
      expect(v.why).to.match(/nothing on-chain says which program/);

      expect(needsVetting((await check(offCurve())).lanes.inspection).offer, "a data-less PDA").to.equal(false);
    });

    it("does not offer one for a wallet, an allowlisted recipient, or one with HIGH findings", async () => {
      const { wallet } = putWallet(chain);
      expect(needsVetting((await check(wallet)).lanes.inspection).offer).to.equal(false);

      const p = key();
      putV3Program(chain, p, { authority: null });
      const pda = offCurve("v", p);
      guard.add("allow", pda, p);
      expect(needsVetting((await check(pda)).lanes.inspection).why).to.match(/already allowlisted/);

      const q = key();
      putV3Program(chain, q, { authority: null });
      guard.add("blockprog", q);
      const b = key();
      chain.set(b, q, Buffer.alloc(8));
      expect(needsVetting((await check(b)).lanes.inspection).offer).to.equal(false);
    });

    it("does not offer one when the chain could not be read", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      chain.failing = true;
      expect(needsVetting((await check(a)).lanes.inspection).offer).to.equal(false);
    });
  });

  describe("acting on a verdict (scripted guard client)", () => {
    const owner = Keypair.generate();
    const agent = Keypair.generate();
    const blocked = async () => {
      const { wallet } = putWallet(chain, { ata: { state: 2 } });
      return check(wallet);
    };
    const vettable = async (amount = "1") => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(a, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: a }));
      return check(a, amount);
    };
    const yes = async () => true;

    it("BLOCK is recorded even when the assess() preview fails, and nothing throws", async () => {
      const { client, sent } = fakeClient({ programId: guard.programId, assess: async () => Promise.reject(new Error("assess needs a funded viewer")) });
      const act = await actOnVerdict(client, { owner, agent }, await blocked());
      expect(act.action).to.equal("recorded-block");
      expect(sent).to.deep.equal(["add deny"]);
      expect(act.messages.join("\n")).to.match(/could not be read: assess needs a funded viewer/);
    });

    it("a BLOCK whose write fails, or lands without the entry, is not called recorded", async () => {
      const failed = fakeClient({ programId: guard.programId, addEntry: landed({ ok: false, landed: false, error: "NotOwner" }) });
      expect((await actOnVerdict(failed.client, { owner, agent }, await blocked())).action).to.equal("block-not-recorded");
      const ghost = fakeClient({ programId: guard.programId, entryAfterWrite: false });
      const act = await actOnVerdict(ghost.client, { owner, agent }, await blocked());
      expect(act.action).to.equal("block-not-recorded");
      expect(act.bridge!.message).to.match(/landed .* but the entry is not there/);
    });

    it("a write that can't be confirmed is judged by whether the entry is there", async () => {
      const { client } = fakeClient({ programId: guard.programId, addEntry: landed({ ok: false, landed: null, error: "could not tell" }) });
      const bridge = await recordVerdictOnChain(client, owner, await blocked());
      expect(bridge.changed).to.equal(true);
    });

    it("BLOCK with no owner key, and BLOCK that needs no write, say so", async () => {
      const { client, sent } = fakeClient({ programId: guard.programId });
      expect((await actOnVerdict(client, { owner: null, agent }, await blocked())).action).to.equal("block-not-recorded");
      const m = key();
      chain.set(m, TOKEN_PROGRAM, Buffer.alloc(82)); // a mint: the guard refuses it by itself
      expect((await actOnVerdict(client, { owner, agent }, await check(m))).action).to.equal("blocked-no-write");
      expect(sent).to.deep.equal([]);
    });

    it("ASK_HUMAN sends nothing", async () => {
      const { client, sent } = fakeClient({ programId: guard.programId });
      expect((await actOnVerdict(client, { owner, agent }, await check(offCurve()))).action).to.equal("asked-human");
      expect(sent).to.deep.equal([]);
    });

    it("PAY is not sent when the guard is stricter, or when its verdict can't be read", async () => {
      const { wallet } = putWallet(chain);
      const r = await check(wallet);
      const stricter = fakeClient({ programId: guard.programId, assess: async () => assessment("BLOCK", "dailyCap") });
      expect((await actOnVerdict(stricter.client, { owner, agent }, r)).action).to.equal("not-sent");
      const unreadable = fakeClient({ programId: guard.programId, assess: () => Promise.reject(new Error("rpc down")) });
      expect((await actOnVerdict(unreadable.client, { owner, agent }, r)).action).to.equal("not-sent");
      expect([...stricter.sent, ...unreadable.sent]).to.deep.equal([]);
    });

    it("a payment that landed and failed, or can't be confirmed, is never called 'not sent'", async () => {
      const { wallet } = putWallet(chain);
      const r = await check(wallet);
      const failed = fakeClient({ programId: guard.programId, pay: landed({ ok: false, landed: true, code: "DAILY_CAP", error: "x" }) });
      expect((await actOnVerdict(failed.client, { owner, agent }, r)).action).to.equal("pay-failed");
      const unknown = fakeClient({ programId: guard.programId, pay: landed({ ok: false, landed: null, error: "could not tell" }) });
      const act = await actOnVerdict(unknown.client, { owner, agent }, r);
      expect(act.action).to.equal("pay-unknown");
      expect(act.messages.join("\n")).to.match(/UNKNOWN whether the payment landed.*Check sig before retrying/);
    });

    it("vetThenPay: a yes allowlists and pays once the guard reads PAY", async () => {
      let allowed = false;
      const { client, sent } = fakeClient({ programId: guard.programId, assess: async () => (allowed ? assessment("PAY") : assessment("REVIEW", "unvettedProgramRecipient")) });
      const realAdd = (client as any).addEntry;
      (client as any).addEntry = async (...args: any[]) => {
        allowed = true;
        return realAdd(...args);
      };
      let question = "";
      const act = await actOnVerdict(client, { owner, agent }, await vettable(), async (q) => {
        question = q;
        return true;
      });
      expect(act.action).to.equal("vetted");
      expect(sent).to.deep.equal(["add allow", "pay"]);
      expect(question).to.match(/keypair address, so whoever holds that key moves the USDC/);
    });

    it("vetThenPay: no payment while the guard still reads REVIEW", async () => {
      const { client, sent } = fakeClient({ programId: guard.programId, assess: async () => assessment("REVIEW", "unvettedProgramRecipient") });
      const v = await vetThenPay(client, { owner, agent }, await vettable(), yes);
      expect(v.paid).to.equal(false);
      expect(sent).to.deep.equal(["add allow"]);
    });

    it("vetThenPay: refuses anything the off-chain verdict didn't PAY", async () => {
      const { client, sent } = fakeClient({ programId: guard.programId });
      const r = await vettable("5000"); // ASK_HUMAN / UNUSUAL_AMOUNT
      expect(r.decision).to.equal("ASK_HUMAN");
      const v = await vetThenPay(client, { owner, agent }, r as AegisResult, yes);
      expect(v.paid).to.equal(false);
      expect(v.messages[0]).to.match(/not PAY/);
      expect(sent).to.deep.equal([]);
    });

    it("confirmOwner: no TTY means no", async () => {
      const was = process.stdin.isTTY;
      (process.stdin as any).isTTY = false;
      const log = console.log;
      console.log = () => {};
      try {
        expect(await confirmOwner("Allowlist it?")).to.equal(false);
      } finally {
        console.log = log;
        (process.stdin as any).isTTY = was;
      }
    });
  });
});

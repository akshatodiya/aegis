// Step 3 on a live local validator: the lanes, aegisCheck, the guard client and
// the bridge against real accounts. Runs after aegis_guard.ts (mocha --sort),
// which initializes the guard; the owner and agent keys are shared with it.
import {
  AuthorityType,
  ExtensionType,
  TOKEN_2022_PROGRAM_ID,
  approve,
  createAssociatedTokenAccount,
  createInitializeMetadataPointerInstruction,
  createInitializeMintInstruction,
  createInitializePermanentDelegateInstruction,
  freezeAccount,
  getAccount,
  getMintLen,
  mintTo,
  setAuthority,
  tokenMetadataInitializeWithRentTransfer,
} from "@solana/spl-token";
import { Connection, Keypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { expect } from "chai";

import { AegisOptions, aegisCheck } from "../src/aegis";
import { connectionReader } from "../src/chain/reader";
import { programFingerprint } from "../src/chain/fingerprint";
import { actOnVerdict, blockTarget, needsVetting, recordVerdictOnChain } from "../src/guard/bridge";
import { GuardClient } from "../src/guard/client";
import { associatedTokenAddress } from "../src/guard/layout";
import { Guard, USDC, loadKeypair, setup, sharedKeys } from "./helpers";

const CLONE_UPGRADEABLE = new PublicKey("5Q4Gk1PaDS9y516fc7C6eYjYLB5MZAn6pj2Cn7V89CdQ");
const CLONE_IMMUTABLE = new PublicKey("9MAnc4HPup3khi7dVf3ShmQYVn7Pk5XBmzRANkRptEkJ");
const yes = async () => true;
const no = async () => false;

describe("lanes on a live validator", () => {
  let g: Guard;
  let client: GuardClient;
  let owner: Keypair;
  let agent: Keypair;
  let payer: Keypair;
  const mintAuthority = loadKeypair("tests/fixtures/mint-authority.json");

  // Every check here runs with the LLM off and a fresh validator's "every
  // program was deployed just now" smoothed out; both have unit tests.
  const opts = (extra: AegisOptions = {}): AegisOptions => ({
    reader: connectionReader(g.connection),
    guard: g.programId,
    reasoner: null,
    recentDeploySlots: 0,
    ...extra,
  });

  async function walletWithAta(): Promise<{ kp: Keypair; ata: PublicKey }> {
    const kp = Keypair.generate();
    const ata = await createAssociatedTokenAccount(g.connection, payer, USDC, kp.publicKey);
    return { kp, ata };
  }

  /** An account whose data `program` owns, at a keypair address, with a USDC account. */
  async function accountOwnedBy(program: PublicKey): Promise<PublicKey> {
    const kp = Keypair.generate();
    const lamports = await g.connection.getMinimumBalanceForRentExemption(8);
    await g.provider.sendAndConfirm(
      new Transaction().add(SystemProgram.createAccount({ fromPubkey: payer.publicKey, newAccountPubkey: kp.publicKey, lamports, space: 8, programId: program })),
      [payer, kp]
    );
    await createAssociatedTokenAccount(g.connection, payer, USDC, kp.publicKey);
    return kp.publicKey;
  }

  async function vaultBalance(): Promise<bigint> {
    const cfg = await client.config();
    return (await getAccount(g.connection, cfg!.vault)).amount;
  }

  before(async () => {
    g = setup();
    ({ owner, agent } = await sharedKeys(g));
    payer = await g.fundedKeypair(10);
    client = new GuardClient(g.connection, g.programId, agent.publicKey);
    const cfg = await client.config();
    expect(cfg, "run with aegis_guard.ts first (mocha --sort)").to.not.equal(null);
    expect((await client.entry("agent", agent.publicKey)).member).to.equal(true);
    await mintTo(g.connection, payer, USDC, cfg!.vault, mintAuthority, 5_000_000_000n);
  });

  it("a clean wallet: PAY off-chain, PAY on-chain, and the treasury rail pays it", async () => {
    const { kp, ata } = await walletWithAta();
    const r = await aegisCheck(kp.publicKey, "5", opts());
    expect([r.decision, r.code]).to.deep.equal(["PAY", null]);
    expect((await client.assess(kp.publicKey, r.amountUnits)).verdict).to.equal("PAY");
    const act = await actOnVerdict(client, { owner, agent }, r, no);
    expect(act.action, act.messages.join("\n")).to.equal("paid");
    expect((await getAccount(g.connection, ata)).amount).to.equal(5_000_000n);
  });

  describe("the delegated-account villain", () => {
    let villain: { kp: Keypair; ata: PublicKey };
    before(async () => {
      villain = await walletWithAta();
      await approve(g.connection, payer, villain.ata, Keypair.generate().publicKey, villain.kp, 2n ** 64n - 1n);
    });

    it("the lane BLOCKs it; the guard alone would only REVIEW it", async () => {
      const r = await aegisCheck(villain.kp.publicKey, "3", opts());
      expect([r.decision, r.code]).to.deep.equal(["BLOCK", "HIGH_RISK_ACCOUNT"]);
      expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("DELEGATED_DESTINATION");
      const onchain = await client.assess(villain.kp.publicKey, r.amountUnits);
      expect([onchain.verdict, onchain.code]).to.deep.equal(["REVIEW", "DELEGATED_DESTINATION"]);
    });

    it("the bridge denylists it on-chain, the guard flips to BLOCK, and a re-run says 'already'", async () => {
      const r = await aegisCheck(villain.kp.publicKey, "3", opts());
      const act = await actOnVerdict(client, { owner, agent }, r, no);
      expect(act.action).to.equal("recorded-block");
      expect(act.bridge!.changed, act.messages.join("\n")).to.equal(true);
      const after = await client.assess(villain.kp.publicKey, r.amountUnits);
      expect([after.verdict, after.code]).to.deep.equal(["BLOCK", "DENYLISTED"]);

      const again = await aegisCheck(villain.kp.publicKey, "3", opts());
      expect(again.code).to.equal("DENYLISTED");
      const rerun = await recordVerdictOnChain(client, owner, again);
      expect(rerun.changed).to.equal(false);
      expect(rerun.message).to.match(/already recorded/);
    });

    it("the injected drain: a direct guarded_pay lands as a failed transaction and the vault doesn't move", async () => {
      const before = await vaultBalance();
      const out = await client.guardedPay(agent, villain.kp.publicKey, 3_000_000n, { skipPreflight: true });
      expect(out.ok).to.equal(false);
      expect(out.landed, "skipPreflight: the refusal is on-chain, fee paid").to.equal(true);
      expect(out.code).to.equal("DENYLISTED");
      expect(out.signature).to.be.a("string");
      expect(await vaultBalance()).to.equal(before);
    });

    it("without skipPreflight the refusal never lands, and still carries its code", async () => {
      const out = await client.guardedPay(agent, villain.kp.publicKey, 3_000_000n);
      expect([out.ok, out.landed, out.code]).to.deep.equal([false, false, "DENYLISTED"]);
    });
  });

  it("frozen and reassigned USDC accounts BLOCK, and the bridge denylists the wallet", async () => {
    const frozen = await walletWithAta();
    await freezeAccount(g.connection, payer, frozen.ata, USDC, mintAuthority);
    const r1 = await aegisCheck(frozen.kp.publicKey, "1", opts());
    expect(r1.decision).to.equal("BLOCK");
    expect(r1.lanes.inspection.facts.map((f) => f.id)).to.include("FROZEN_DESTINATION");

    const moved = await walletWithAta();
    await setAuthority(g.connection, payer, moved.ata, moved.kp, AuthorityType.AccountOwner, Keypair.generate().publicKey);
    const r2 = await aegisCheck(moved.kp.publicKey, "1", opts());
    expect(r2.lanes.inspection.facts.map((f) => f.id)).to.include("DESTINATION_OWNER_MISMATCH");
    const t = blockTarget(r2, g.programId);
    expect(t.kind).to.equal("deny");
  });

  it("a wallet with no USDC account is ASK_HUMAN; the client creates one only for a wallet", async () => {
    const fresh = Keypair.generate().publicKey;
    const r = await aegisCheck(fresh, "1", opts());
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "MEDIUM_RISK_ACCOUNT"]);
    expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("DESTINATION_MISSING");

    const made = await client.ensureRecipientAta(agent, fresh);
    expect(made.created).to.equal(true);
    expect((await aegisCheck(fresh, "1", opts())).decision).to.equal("PAY");
    expect((await client.ensureRecipientAta(agent, fresh)).created).to.equal(false);

    const [pda] = PublicKey.findProgramAddressSync([Buffer.from("x")], CLONE_IMMUTABLE);
    let threw = false;
    try {
      await client.ensureRecipientAta(agent, pda);
    } catch (e: any) {
      threw = /program-controlled/.test(e.message);
    }
    expect(threw).to.equal(true);
  });

  it("lamports a stranger sends to a fresh wallet's ATA address: still ASK_HUMAN, nothing denylisted, and the ATA can be created", async () => {
    const fresh = Keypair.generate().publicKey;
    const ata = associatedTokenAddress(fresh, USDC);
    const rent = await g.connection.getMinimumBalanceForRentExemption(0);
    await g.provider.sendAndConfirm(new Transaction().add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: ata, lamports: rent })), [payer]);

    const r = await aegisCheck(fresh, "1", opts());
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "MEDIUM_RISK_ACCOUNT"]);
    const act = await actOnVerdict(client, { owner, agent }, r, no);
    expect(act.action).to.equal("asked-human");
    expect((await client.entry("deny", fresh)).member).to.equal(false);

    const made = await client.ensureRecipientAta(agent, fresh);
    expect(made.created, made.outcome?.error ?? "").to.equal(true);
    expect((await aegisCheck(fresh, "1", opts())).decision).to.equal("PAY");
  });

  it("the guard program itself as recipient: HIGH, with its upgrade authority read from ProgramData", async () => {
    const r = await aegisCheck(g.programId, "1", opts());
    expect(r.decision).to.equal("BLOCK");
    expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("PROGRAM_RECIPIENT");
    const self = r.lanes.inspection.programs.find((p) => p.id === g.programId.toBase58())!;
    expect(self.upgradeAuthority).to.equal(g.provider.wallet.publicKey.toBase58());
    expect(blockTarget(r, g.programId).kind, "the guard refuses programs by itself").to.equal("none");
  });

  it("an account owned by an upgradeable program is ASK_HUMAN, naming the authority", async () => {
    const acct = await accountOwnedBy(CLONE_UPGRADEABLE);
    const r = await aegisCheck(acct, "1", opts());
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "MEDIUM_RISK_ACCOUNT"]);
    const up = r.lanes.inspection.facts.find((f) => f.id === "UPGRADEABLE_PROGRAM")!;
    expect(up.data!.upgradeAuthority).to.equal(g.provider.wallet.publicKey.toBase58());
  });

  it("with the default threshold, a program deployed at genesis is 'recently deployed'", async () => {
    const acct = await accountOwnedBy(CLONE_IMMUTABLE);
    const r = await aegisCheck(acct, "1", opts({ recentDeploySlots: undefined }));
    expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("RECENTLY_DEPLOYED");
  });

  describe("an account owned by an immutable program", () => {
    let acct: PublicKey;
    before(async () => {
      acct = await accountOwnedBy(CLONE_IMMUTABLE);
    });

    it("the lane says PAY; the guard says REVIEW until someone vets it", async () => {
      const r = await aegisCheck(acct, "2", opts());
      expect(r.decision, r.reasons.join("\n")).to.equal("PAY");
      expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("IMMUTABLE_PROGRAM");
      const onchain = await client.assess(acct, r.amountUnits);
      expect([onchain.verdict, onchain.code]).to.deep.equal(["REVIEW", "UNVETTED_PROGRAM_RECIPIENT"]);
      const vet = needsVetting(r.lanes.inspection);
      expect(vet.offer).to.equal(true);
      // a keypair address: the keypair signs for its USDC account, not the data owner
      expect(vet.controller).to.equal(null);
    });

    it("an owner who says no leaves it at REVIEW and sends nothing", async () => {
      const r = await aegisCheck(acct, "2", opts());
      const act = await actOnVerdict(client, { owner, agent }, r, no);
      expect(act.action).to.equal("not-sent");
      expect(act.messages.join("\n")).to.match(/leaving it at REVIEW/);
      expect((await client.entry("allow", acct)).member).to.equal(false);
    });

    it("an owner who says yes allowlists it, and the payment goes out", async () => {
      const r = await aegisCheck(acct, "2", opts());
      const act = await actOnVerdict(client, { owner, agent }, r, yes);
      expect(act.action, act.messages.join("\n")).to.equal("vetted");
      const entry = await client.entry("allow", acct);
      expect(entry.member).to.equal(true);
      expect(entry.controller).to.equal(null);
      expect((await getAccount(g.connection, associatedTokenAddress(acct, USDC))).amount).to.equal(2_000_000n);
    });
  });

  it("blocking a program by id reaches every account it controls, and is idempotent", async () => {
    const a = await accountOwnedBy(CLONE_UPGRADEABLE);
    const b = await accountOwnedBy(CLONE_UPGRADEABLE);
    const sent = await client.addEntry(owner, "blockprog", CLONE_UPGRADEABLE);
    expect(sent.ok, sent.error ?? "").to.equal(true);
    for (const acct of [a, b]) {
      const r = await aegisCheck(acct, "1", opts());
      expect([r.decision, r.code]).to.deep.equal(["BLOCK", "HIGH_RISK_ACCOUNT"]);
      expect(r.lanes.inspection.facts.map((f) => f.id)).to.include("BLOCKED_PROGRAM");
      expect((await client.assess(acct, 1_000_000n)).code).to.equal("BLOCKED_PROGRAM");
      const t = blockTarget(r, g.programId);
      expect([t.kind, (t as any).key?.toBase58()]).to.deep.equal(["blockprog", CLONE_UPGRADEABLE.toBase58()]);
      expect((await recordVerdictOnChain(client, owner, r)).message).to.match(/already recorded/);
    }
  });

  it("a PDA with no account is ASK_HUMAN, and no allowlist is offered", async () => {
    const [pda] = PublicKey.findProgramAddressSync([Buffer.from("escrow")], Keypair.generate().publicKey);
    const r = await aegisCheck(pda, "1", opts());
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "MEDIUM_RISK_ACCOUNT"]);
    expect(needsVetting(r.lanes.inspection).offer).to.equal(false);
    expect((await client.assess(pda, 1_000_000n)).code).to.equal("UNVETTED_PROGRAM_RECIPIENT");
  });

  it("the look-alike mint: a real Token-2022 'USD Coin' with a permanent delegate is HIGH", async () => {
    const mint = Keypair.generate();
    const mintLen = getMintLen([ExtensionType.PermanentDelegate, ExtensionType.MetadataPointer]);
    const lamports = await g.connection.getMinimumBalanceForRentExemption(mintLen);
    const clawback = Keypair.generate().publicKey;
    await g.provider.sendAndConfirm(
      new Transaction().add(
        SystemProgram.createAccount({ fromPubkey: payer.publicKey, newAccountPubkey: mint.publicKey, space: mintLen, lamports, programId: TOKEN_2022_PROGRAM_ID }),
        createInitializePermanentDelegateInstruction(mint.publicKey, clawback, TOKEN_2022_PROGRAM_ID),
        createInitializeMetadataPointerInstruction(mint.publicKey, payer.publicKey, mint.publicKey, TOKEN_2022_PROGRAM_ID),
        createInitializeMintInstruction(mint.publicKey, 6, payer.publicKey, payer.publicKey, TOKEN_2022_PROGRAM_ID)
      ),
      [payer, mint]
    );
    await tokenMetadataInitializeWithRentTransfer(g.connection, payer, mint.publicKey, payer.publicKey, payer, "USD Coin", "USDC", "https://example.invalid/usdc.json", [], undefined, TOKEN_2022_PROGRAM_ID);

    const { kp } = await walletWithAta();
    const r = await aegisCheck(kp.publicKey, "1", opts({ mint: mint.publicKey }));
    const ids = r.lanes.inspection.facts.map((f) => f.id);
    expect(ids).to.include.members(["NOT_PINNED_ASSET", "PERMANENT_DELEGATE", "SPOOFED_METADATA", "FREEZE_AUTHORITY"]);
    expect(r.decision).to.equal("BLOCK");
    expect(r.lanes.inspection.facts.find((f) => f.id === "PERMANENT_DELEGATE")!.data!.delegate).to.equal(clawback.toBase58());
    expect(blockTarget(r, g.programId).kind, "mint findings map to no guard list").to.equal("none");
  });

  it("history: after a guarded payment, 5x of it is PAY and past 5x is ASK_HUMAN", async () => {
    const { kp } = await walletWithAta();
    expect((await aegisCheck(kp.publicKey, "40", opts())).decision).to.equal("PAY");
    const paid = await client.guardedPay(agent, kp.publicKey, 40_000_000n);
    expect(paid.ok, paid.error ?? "").to.equal(true);
    expect((await aegisCheck(kp.publicKey, "200", opts())).decision).to.equal("PAY");
    const r = await aegisCheck(kp.publicKey, "201", opts());
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "UNUSUAL_AMOUNT"]);
    expect(r.lanes.behavior.history).to.deep.equal({ count: 1, largest: 40_000_000n });
  });

  it("an RPC that is down: ASK_HUMAN / LANE_UNAVAILABLE, never PAY", async () => {
    const dead = connectionReader(new Connection("http://127.0.0.1:1", "confirmed"));
    const r = await aegisCheck(Keypair.generate().publicKey, "1", opts({ reader: dead }));
    expect([r.decision, r.code]).to.deep.equal(["ASK_HUMAN", "LANE_UNAVAILABLE"]);
  });

  it("the fingerprint matches a byte-identical copy of the guard's code under another id", async () => {
    const reader = connectionReader(g.connection);
    const original = await programFingerprint(reader, g.programId);
    const clone = await programFingerprint(reader, CLONE_UPGRADEABLE);
    expect(original).to.not.equal(null);
    expect(clone!.raw).to.equal(original!.raw);
    expect(original!.elfBytes).to.be.greaterThan(1000);
  });
});

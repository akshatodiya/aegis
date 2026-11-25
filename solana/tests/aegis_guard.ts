import { BN } from "@anchor-lang/core";
import {
  AuthorityType,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  approve,
  createAccount,
  createAssociatedTokenAccount,
  createMint,
  freezeAccount,
  getAccount,
  getAssociatedTokenAddressSync,
  mintTo,
  setAuthority,
} from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { expect } from "chai";

import { Guard, USDC, expectError, loadKeypair, setup, sharedKeys, usdc } from "./helpers";

// Order matters: the config PDA is global, so the suite runs as one story.
describe("aegis_guard", () => {
  let g: Guard;
  let deployer: PublicKey;
  const mintAuthority = loadKeypair("tests/fixtures/mint-authority.json");
  let owner: Keypair;
  let agent: Keypair;
  let outsider: Keypair;
  let vault: PublicKey;

  // A plain wallet with a clean USDC ATA: the good recipient.
  const alice = Keypair.generate();
  let aliceAta: PublicKey;

  const DAILY_LIMIT = usdc(1_000);

  async function newWalletWithAta(): Promise<{ kp: Keypair; ata: PublicKey }> {
    const kp = Keypair.generate();
    const ata = await createAssociatedTokenAccount(g.connection, outsider, USDC, kp.publicKey);
    return { kp, ata };
  }

  async function vaultBalance(): Promise<bigint> {
    return (await getAccount(g.connection, vault)).amount;
  }

  before(async () => {
    g = setup();
    deployer = g.provider.wallet.publicKey;
    ({ owner, agent } = await sharedKeys(g));
    outsider = await g.fundedKeypair();
    aliceAta = await createAssociatedTokenAccount(g.connection, outsider, USDC, alice.publicKey);
    vault = getAssociatedTokenAddressSync(USDC, g.config, true);
  });

  describe("initialize", () => {
    const initAccounts = (signer: PublicKey, mint = USDC) => ({
      deployer: signer,
      programData: g.programData,
      config: g.config,
      audit: g.audit,
      mint,
      vault: getAssociatedTokenAddressSync(mint, g.config, true),
    });

    it("refuses a signer that is not the upgrade authority", async () => {
      await expectError(
        g.program.methods
          .initialize(owner.publicKey, DAILY_LIMIT)
          .accountsPartial(initAccounts(outsider.publicKey))
          .signers([outsider])
          .rpc(),
        "NotUpgradeAuthority"
      );
    });

    it("refuses a Token-2022 mint", async () => {
      const t22 = await createMint(
        g.connection,
        outsider,
        outsider.publicKey,
        null,
        6,
        Keypair.generate(),
        undefined,
        TOKEN_2022_PROGRAM_ID
      );
      await expectError(
        g.program.methods
          .initialize(owner.publicKey, DAILY_LIMIT)
          .accountsPartial({
            ...initAccounts(deployer, t22),
            vault: getAssociatedTokenAddressSync(t22, g.config, true, TOKEN_2022_PROGRAM_ID),
          })
          .rpc(),
        "AccountOwnedByWrongProgram"
      );
    });

    it("initializes with the upgrade authority, even if the vault ATA was pre-created", async () => {
      // Anyone can create the config PDA's ATA first; that must not brick init.
      await createAssociatedTokenAccount(g.connection, outsider, USDC, g.config, undefined, undefined, undefined, true);
      await g.program.methods
        .initialize(owner.publicKey, DAILY_LIMIT)
        .accountsPartial(initAccounts(deployer))
        .rpc();

      const cfg = await g.program.account.config.fetch(g.config);
      expect(cfg.owner.toBase58()).to.equal(owner.publicKey.toBase58());
      expect(cfg.mint.toBase58()).to.equal(USDC.toBase58());
      expect(cfg.vault.toBase58()).to.equal(vault.toBase58());
      expect(cfg.dailyLimit.toString()).to.equal(DAILY_LIMIT.toString());
      expect(cfg.paused).to.equal(false);
      expect(cfg.pendingOwner).to.equal(null);

      const v = await getAccount(g.connection, vault);
      expect(v.owner.toBase58()).to.equal(g.config.toBase58());
      expect(v.delegate).to.equal(null);
      expect(v.closeAuthority).to.equal(null);

      const audit = await g.program.account.auditLog.fetch(g.audit);
      expect(audit.totalRefusals.toNumber()).to.equal(0);
    });

    it("cannot be initialized twice", async () => {
      await expectError(
        g.program.methods
          .initialize(outsider.publicKey, DAILY_LIMIT)
          .accountsPartial(initAccounts(deployer))
          .rpc(),
        "already in use"
      );
    });

    after(async () => {
      await mintTo(g.connection, outsider, USDC, vault, mintAuthority, 10_000_000_000n);
    });
  });

  describe("guarded_pay: the clean path", () => {
    it("refuses a signer that is not an agent", async () => {
      await expectError(g.pay(agent, alice.publicKey, aliceAta, usdc(1)), "NotAgent");
    });

    it("pays a plain wallet once the agent is added, and emits Paid", async () => {
      await g.addEntry(owner, "agent", agent.publicKey);
      expect(await g.isEntry("agent", agent.publicKey)).to.equal(true);

      const a = await g.assess(alice.publicKey, aliceAta, usdc(10));
      expect(a.verdict).to.equal("pay");
      expect(a.reason).to.equal("clear");

      const before = await vaultBalance();
      const sig = await g.pay(agent, alice.publicKey, aliceAta, usdc(10));
      expect(before - (await vaultBalance())).to.equal(10_000_000n);
      expect((await getAccount(g.connection, aliceAta)).amount).to.equal(10_000_000n);

      const events = await g.cpiEvents(sig);
      expect(events.map((e) => e.name)).to.deep.equal(["paid"]);
      const paid = events[0].data;
      expect(paid.id.toNumber()).to.equal(1);
      expect(paid.agent.toBase58()).to.equal(agent.publicKey.toBase58());
      expect(paid.recipient.toBase58()).to.equal(alice.publicKey.toBase58());
      expect(paid.destination.toBase58()).to.equal(aliceAta.toBase58());
      expect(paid.amount.toString()).to.equal(usdc(10).toString());
      expect(paid.spentToday.toString()).to.equal(usdc(10).toString());
    });

    it("keeps per-recipient stats that only guarded_pay writes", async () => {
      await g.pay(agent, alice.publicKey, aliceAta, usdc(25));
      const s = await g.program.account.stats.fetch(g.statsPda(alice.publicKey));
      expect(s.count.toNumber()).to.equal(2);
      expect(s.largest.toString()).to.equal(usdc(25).toString());
      expect(s.total.toString()).to.equal(usdc(35).toString());
      const cfg = await g.program.account.config.fetch(g.config);
      expect(cfg.payCount.toNumber()).to.equal(2);
      expect(cfg.spentToday.toString()).to.equal(usdc(35).toString());
    });

    it("refuses a zero amount", async () => {
      await expectError(g.pay(agent, alice.publicKey, aliceAta, new BN(0)), "BadAmount");
    });
  });

  describe("recipient classification", () => {
    it("blocks sinks: the default key, the incinerator, config, vault and the audit log", async () => {
      const incinerator = new PublicKey("1nc1nerator11111111111111111111111111111111");
      for (const r of [PublicKey.default, incinerator, g.config, vault, g.audit]) {
        const a = await g.assess(r, aliceAta, usdc(1));
        expect([a.verdict, a.reason], r.toBase58()).to.deep.equal(["block", "sinkRecipient"]);
      }
      await expectError(g.pay(agent, PublicKey.default, aliceAta, usdc(1)), "SinkRecipient");
    });

    it("blocks programs, ProgramData, mints, token accounts and sysvars", async () => {
      const tokenAcct = await createAccount(g.connection, outsider, USDC, outsider.publicKey, Keypair.generate());
      const cases: [PublicKey, string][] = [
        [g.programId, "programRecipient"],
        [g.programData, "programRecipient"],
        [TOKEN_PROGRAM_ID, "programRecipient"],
        [USDC, "tokenAccountRecipient"],
        [tokenAcct, "tokenAccountRecipient"],
        [SYSVAR_CLOCK_PUBKEY, "sysvarRecipient"],
      ];
      for (const [r, reason] of cases) {
        const a = await g.assess(r, aliceAta, usdc(1));
        expect([a.verdict, a.reason], r.toBase58()).to.deep.equal(["block", reason]);
      }
      await expectError(g.pay(agent, g.programId, aliceAta, usdc(1)), "ProgramRecipient");
    });

    it("sends a PDA recipient to REVIEW, and allowlisting it flips it to PAY", async () => {
      const controller = Keypair.generate().publicKey; // stands in for the program that signs for the PDA
      const [pdaRecipient] = PublicKey.findProgramAddressSync([Buffer.from("escrow")], controller);
      const ata = await createAssociatedTokenAccount(g.connection, outsider, USDC, pdaRecipient, undefined, undefined, undefined, true);

      let a = await g.assess(pdaRecipient, ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "unvettedProgramRecipient"]);
      await expectError(g.pay(agent, pdaRecipient, ata, usdc(1)), "UnvettedProgramRecipient");

      await g.addEntry(owner, "allow", pdaRecipient, controller);
      a = await g.assess(pdaRecipient, ata, usdc(1));
      expect(a.verdict).to.equal("pay");
      await g.pay(agent, pdaRecipient, ata, usdc(1));

      // The allow entry names a controller, so leaving its blockprog account out fails.
      await expectError(
        g.pay(agent, pdaRecipient, ata, usdc(1), { blockprogController: null }),
        "MissingControllerEntry"
      );

      // Blocking the controller beats the earlier allow.
      await g.addEntry(owner, "blockprog", controller);
      a = await g.assess(pdaRecipient, ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "blockedProgram"]);
      await expectError(g.pay(agent, pdaRecipient, ata, usdc(1)), "BlockedProgram");
    });

    it("treats an on-curve account with program-owned data as program-controlled, and blocks by owner", async () => {
      const fakeProgram = Keypair.generate().publicKey;
      const kp = Keypair.generate();
      const lamports = await g.connection.getMinimumBalanceForRentExemption(8);
      await g.provider.sendAndConfirm(
        new Transaction().add(
          SystemProgram.createAccount({
            fromPubkey: outsider.publicKey,
            newAccountPubkey: kp.publicKey,
            lamports,
            space: 8,
            programId: fakeProgram,
          })
        ),
        [outsider, kp]
      );
      const ata = await createAssociatedTokenAccount(g.connection, outsider, USDC, kp.publicKey);

      let a = await g.assess(kp.publicKey, ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "unvettedProgramRecipient"]);

      await g.addEntry(owner, "blockprog", fakeProgram);
      a = await g.assess(kp.publicKey, ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "blockedProgram"]);

      // An allow entry doesn't override a block on the owning program.
      await g.addEntry(owner, "allow", kp.publicKey);
      a = await g.assess(kp.publicKey, ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "blockedProgram"]);
    });

    it("rejects a blockprog account that is not the canonical PDA for the recipient's owner", async () => {
      await expectError(
        g.pay(agent, alice.publicKey, aliceAta, usdc(1), {
          blockprogOwner: g.entryPda("blockprog", Keypair.generate().publicKey),
        }),
        "BadEntryAccount"
      );
    });
  });

  describe("destination token account", () => {
    it("blocks a destination whose owner was reassigned away from the recipient", async () => {
      const bob = await newWalletWithAta();
      const thief = Keypair.generate().publicKey;
      await setAuthority(g.connection, outsider, bob.ata, bob.kp, AuthorityType.AccountOwner, thief);
      const a = await g.assess(bob.kp.publicKey, bob.ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "destinationOwnerMismatch"]);
      await expectError(g.pay(agent, bob.kp.publicKey, bob.ata, usdc(1)), "DestinationOwnerMismatch");
    });

    it("sends a destination with a live delegate to REVIEW", async () => {
      const villain = await newWalletWithAta();
      const attacker = Keypair.generate().publicKey;
      await approve(g.connection, outsider, villain.ata, attacker, villain.kp, 1_000_000_000n);
      const a = await g.assess(villain.kp.publicKey, villain.ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "delegatedDestination"]);
      const before = await vaultBalance();
      await expectError(g.pay(agent, villain.kp.publicKey, villain.ata, usdc(1)), "DelegatedDestination");
      expect(await vaultBalance()).to.equal(before);
    });

    it("blocks a frozen destination", async () => {
      const carol = await newWalletWithAta();
      await freezeAccount(g.connection, outsider, carol.ata, USDC, mintAuthority);
      const a = await g.assess(carol.kp.publicKey, carol.ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "frozenDestination"]);
      await expectError(g.pay(agent, carol.kp.publicKey, carol.ata, usdc(1)), "FrozenDestination");
    });

    it("blocks a destination for another mint, or one that is not a token account", async () => {
      const other = await createMint(g.connection, outsider, outsider.publicKey, null, 6);
      const otherAta = await createAssociatedTokenAccount(g.connection, outsider, other, alice.publicKey);
      let a = await g.assess(alice.publicKey, otherAta, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "badDestination"]);
      a = await g.assess(alice.publicKey, alice.publicKey, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "badDestination"]);
    });
  });

  describe("lists", () => {
    it("denylist blocks, and deny is checked before allow", async () => {
      const dave = await newWalletWithAta();
      await g.addEntry(owner, "allow", dave.kp.publicKey);
      await g.addEntry(owner, "deny", dave.kp.publicKey);
      const a = await g.assess(dave.kp.publicKey, dave.ata, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["block", "denylisted"]);
      await expectError(g.pay(agent, dave.kp.publicKey, dave.ata, usdc(1)), "Denylisted");

      await g.removeEntry(owner, "deny", dave.kp.publicKey);
      expect((await g.assess(dave.kp.publicKey, dave.ata, usdc(1))).verdict).to.equal("pay");
    });

    it("pre-funded entry addresses count as absent", async () => {
      // Anyone can send lamports to any address. That must not add or remove anyone.
      const erin = await newWalletWithAta();
      await g.prefund(g.entryPda("deny", erin.kp.publicKey));
      expect((await g.assess(erin.kp.publicKey, erin.ata, usdc(1))).verdict).to.equal("pay");

      const [pdaRecipient] = PublicKey.findProgramAddressSync([Buffer.from("vault")], Keypair.generate().publicKey);
      const pdaAta = await createAssociatedTokenAccount(g.connection, outsider, USDC, pdaRecipient, undefined, undefined, undefined, true);
      await g.prefund(g.entryPda("allow", pdaRecipient));
      expect((await g.assess(pdaRecipient, pdaAta, usdc(1))).reason).to.equal("unvettedProgramRecipient");

      await g.prefund(g.entryPda("agent", outsider.publicKey));
      await expectError(g.pay(outsider, alice.publicKey, aliceAta, usdc(1)), "NotAgent");

      // And the owner can still add an entry at a pre-funded address.
      await g.addEntry(owner, "deny", erin.kp.publicKey);
      expect((await g.assess(erin.kp.publicKey, erin.ata, usdc(1))).reason).to.equal("denylisted");
    });

    it("adding an entry twice is idempotent", async () => {
      await g.addEntry(owner, "agent", agent.publicKey);
      expect(await g.isEntry("agent", agent.publicKey)).to.equal(true);
    });
  });

  describe("kill switch and limits", () => {
    it("a revoked agent is refused while assess still says PAY, and restore works", async () => {
      await g.removeEntry(owner, "agent", agent.publicKey);
      expect(await g.isEntry("agent", agent.publicKey)).to.equal(false);
      expect((await g.assess(alice.publicKey, aliceAta, usdc(1))).verdict).to.equal("pay");
      await expectError(g.pay(agent, alice.publicKey, aliceAta, usdc(1)), "NotAgent");

      await g.addEntry(owner, "agent", agent.publicKey);
      await g.pay(agent, alice.publicKey, aliceAta, usdc(1));
    });

    it("paused refuses every pay, and withdraw still works", async () => {
      await g.program.methods.setPaused(true).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();
      const a = await g.assess(alice.publicKey, aliceAta, usdc(1));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "paused"]);
      await expectError(g.pay(agent, alice.publicKey, aliceAta, usdc(1)), "Paused");

      const ownerAta = await createAssociatedTokenAccount(g.connection, outsider, USDC, owner.publicKey);
      await g.program.methods
        .withdraw(usdc(5))
        .accountsPartial({ owner: owner.publicKey, config: g.config, vault, mint: USDC, to: ownerAta })
        .signers([owner])
        .rpc();
      expect((await getAccount(g.connection, ownerAta)).amount).to.equal(5_000_000n);

      await g.program.methods.setPaused(false).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();
      expect((await g.assess(alice.publicKey, aliceAta, usdc(1))).verdict).to.equal("pay");
    });

    it("the daily cap sends an over-limit payment to REVIEW, and refills draw on it", async () => {
      const cfg = await g.program.account.config.fetch(g.config);
      const limit = cfg.spentToday.add(usdc(50));
      await g.program.methods.setDailyLimit(limit).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();

      // A float refill is just another guarded payment: it counts toward the cap.
      const float = await newWalletWithAta();
      await g.pay(agent, float.kp.publicKey, float.ata, usdc(40));

      let a = await g.assess(alice.publicKey, aliceAta, usdc(11));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "dailyCap"]);
      await expectError(g.pay(agent, alice.publicKey, aliceAta, usdc(11)), "DailyCap");
      await g.pay(agent, alice.publicKey, aliceAta, usdc(10)); // exactly at the limit
      a = await g.assess(alice.publicKey, aliceAta, usdc(0.000001));
      expect(a.reason).to.equal("dailyCap");
    });

    it("daily_limit = 0 freezes payments", async () => {
      await g.program.methods.setDailyLimit(new BN(0)).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();
      const a = await g.assess(alice.publicKey, aliceAta, usdc(0.000001));
      expect([a.verdict, a.reason]).to.deep.equal(["review", "dailyCap"]);
      await g.program.methods.setDailyLimit(usdc(1_000_000)).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();
      expect((await g.assess(alice.publicKey, aliceAta, usdc(1))).verdict).to.equal("pay");
    });
  });

  describe("owner", () => {
    it("every setter and withdraw is owner-only", async () => {
      const as = { owner: outsider.publicKey, config: g.config };
      await expectError(g.program.methods.setDailyLimit(usdc(1)).accountsPartial(as).signers([outsider]).rpc(), "NotOwner");
      await expectError(g.program.methods.setPaused(true).accountsPartial(as).signers([outsider]).rpc(), "NotOwner");
      await expectError(g.program.methods.transferOwnership(outsider.publicKey).accountsPartial(as).signers([outsider]).rpc(), "NotOwner");
      await expectError(g.addEntry(outsider, "agent", outsider.publicKey), "NotOwner");
      await expectError(g.removeEntry(outsider, "agent", agent.publicKey), "NotOwner");
      const outsiderAta = await createAssociatedTokenAccount(g.connection, outsider, USDC, outsider.publicKey);
      await expectError(
        g.program.methods
          .withdraw(usdc(1))
          .accountsPartial({ owner: outsider.publicKey, config: g.config, vault, mint: USDC, to: outsiderAta })
          .signers([outsider])
          .rpc(),
        "NotOwner"
      );
    });

    it("ownership moves in two steps", async () => {
      const next = await g.fundedKeypair(1);
      await g.program.methods.transferOwnership(next.publicKey).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc();
      expect((await g.program.account.config.fetch(g.config)).owner.toBase58()).to.equal(owner.publicKey.toBase58());

      await expectError(
        g.program.methods.acceptOwnership().accountsPartial({ newOwner: outsider.publicKey, config: g.config }).signers([outsider]).rpc(),
        "NotPendingOwner"
      );
      await g.program.methods.acceptOwnership().accountsPartial({ newOwner: next.publicKey, config: g.config }).signers([next]).rpc();
      const cfg = await g.program.account.config.fetch(g.config);
      expect(cfg.owner.toBase58()).to.equal(next.publicKey.toBase58());
      expect(cfg.pendingOwner).to.equal(null);
      await expectError(
        g.program.methods.setPaused(true).accountsPartial({ owner: owner.publicKey, config: g.config }).signers([owner]).rpc(),
        "NotOwner"
      );

      // hand it back for the rest of the suite
      await g.program.methods.transferOwnership(owner.publicKey).accountsPartial({ owner: next.publicKey, config: g.config }).signers([next]).rpc();
      await g.program.methods.acceptOwnership().accountsPartial({ newOwner: owner.publicKey, config: g.config }).signers([owner]).rpc();
    });
  });

  describe("refusal log", () => {
    it("is gated to reporters", async () => {
      await expectError(g.logRefusal(outsider, {}).rpc(), "NotReporter");
    });

    it("records consecutive ids and emits Refused", async () => {
      await g.addEntry(owner, "reporter", agent.publicKey);
      const s1 = await g.logRefusal(agent, { recipient: alice.publicKey, amount: usdc(3), code: "DENYLISTED" }).rpc();
      const s2 = await g.logRefusal(agent, { verdict: { askHuman: {} }, code: "UNUSUAL_AMOUNT", reason: "5x the largest" }).rpc();
      const [e1] = await g.cpiEvents(s1);
      const [e2] = await g.cpiEvents(s2);
      expect(e1.name).to.equal("refused");
      expect(e1.data.id.toNumber()).to.equal(1);
      expect(e1.data.recipient.toBase58()).to.equal(alice.publicKey.toBase58());
      expect(Object.keys(e1.data.verdict)[0]).to.equal("block");
      expect(e2.data.id.toNumber()).to.equal(2);
      expect(e2.data.recipient).to.equal(null);
      expect(Object.keys(e2.data.verdict)[0]).to.equal("askHuman");
      expect(e2.data.code).to.equal("UNUSUAL_AMOUNT");
      expect((await g.program.account.auditLog.fetch(g.audit)).totalRefusals.toNumber()).to.equal(2);
    });

    it("takes a 1-256 byte reason and an A-Z_ code", async () => {
      await expectError(g.logRefusal(agent, { reason: "" }).rpc(), "BadReason");
      await g.logRefusal(agent, { reason: "x".repeat(256) }).rpc();
      await expectError(g.logRefusal(agent, { reason: "x".repeat(257) }).rpc(), "BadReason");
      await expectError(g.logRefusal(agent, { code: "" }).rpc(), "BadCode");
      await expectError(g.logRefusal(agent, { code: "lower" }).rpc(), "BadCode");
      await expectError(g.logRefusal(agent, { code: "A".repeat(33) }).rpc(), "BadCode");
    });

    it("cannot record a PAY", async () => {
      const ix = await g.logRefusal(agent, {}).instruction();
      // 8-byte discriminator, then Option<Pubkey> None (1), then amount (8), then the verdict byte.
      expect(ix.data[17]).to.equal(0);
      ix.data[17] = 2;
      await expectError(g.provider.sendAndConfirm(new Transaction().add(ix), [agent]), "InstructionDidNotDeserialize");
    });
  });
});

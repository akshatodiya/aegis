import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";

import { Fact, inspect } from "../../src/lanes/inspection";
import { associatedTokenAddress } from "../../src/guard/layout";
import { BPF_LOADER_2, INCINERATOR, NATIVE_LOADER, STAKE_PROGRAM, SYSVAR_OWNER } from "../../src/config";
import {
  FakeChain,
  SYSTEM_PROGRAM,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  USDC_MINT,
  key,
  metadataValue,
  mintBytes,
  offCurve,
  putGuard,
  putV2Program,
  putV3Program,
  putV4Program,
  putWallet,
  tlv,
  token2022MintBytes,
  tokenAccountBytes,
} from "./fixtures";

const ids = (r: { facts: Fact[] }) => r.facts.map((f) => f.id);
const fact = (r: { facts: Fact[] }, id: string) => r.facts.find((f) => f.id === id);

describe("unit: inspection lane", () => {
  let chain: FakeChain;
  let guard: ReturnType<typeof putGuard>;
  beforeEach(() => {
    chain = new FakeChain();
    guard = putGuard(chain);
  });
  const run = (recipient: PublicKey, extra = {}) => inspect(recipient, { reader: chain, guard: guard.programId, amount: 10_000_000n, ...extra });

  describe("plain wallets", () => {
    it("a funded wallet with a clean USDC account is LOW", async () => {
      const { wallet, ata } = putWallet(chain);
      const r = await run(wallet);
      expect(r.level).to.equal("LOW");
      expect(r.kind).to.equal("wallet");
      expect(ids(r)).to.deep.equal(["WALLET"]);
      expect(r.destination!.address).to.equal(ata.toBase58());
      expect(r.onchain).to.deep.equal({ denied: false, allow: null });
      expect(r.reason).to.match(/plain wallet/).and.match(/clean/);
    });

    it("an address with no account yet is still a wallet if it is on the curve", async () => {
      const { wallet } = putWallet(chain, { lamports: false });
      const r = await run(wallet);
      expect([r.level, r.kind]).to.deep.equal(["LOW", "wallet"]);
      expect(fact(r, "WALLET")!.detail).to.match(/no account yet/);
    });

    it("a wallet with no USDC account is MEDIUM: the payer would fund its rent", async () => {
      const { wallet } = putWallet(chain, { ata: null });
      const r = await run(wallet);
      expect(r.level).to.equal("MEDIUM");
      expect(ids(r)).to.include("DESTINATION_MISSING");
    });

    it("a System account holding data (a nonce) is LOW but named", async () => {
      const w = key();
      chain.set(w, SYSTEM_PROGRAM, Buffer.alloc(80));
      chain.set(associatedTokenAddress(w, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: w }));
      const r = await run(w);
      expect([r.level, r.kind]).to.deep.equal(["LOW", "system-account"]);
      expect(ids(r)).to.include("SYSTEM_ACCOUNT_WITH_DATA");
    });
  });

  describe("recipient types the guard refuses by itself", () => {
    it("sinks: default key, incinerator, the guard's config, audit log and vault", async () => {
      for (const r of [PublicKey.default, INCINERATOR, guard.pdas.config, guard.pdas.audit, guard.vault]) {
        const res = await run(r);
        expect([res.level, res.kind], r.toBase58()).to.deep.equal(["HIGH", "sink"]);
        expect(fact(res, "SINK_RECIPIENT")!).to.include({ guardEnforced: true });
        expect(res.destination, "no destination checks for a sink").to.equal(null);
      }
    });

    it("any account owned by the guard program is a sink", async () => {
      const a = key();
      chain.set(a, guard.programId, Buffer.alloc(10));
      expect((await run(a)).kind).to.equal("sink");
    });

    it("programs, ProgramData, buffers and native programs are HIGH", async () => {
      const prog = key();
      putV3Program(chain, prog, { authority: key(), slot: 5n });
      const r = await run(prog);
      expect([r.level, r.kind]).to.deep.equal(["HIGH", "program"]);
      expect(fact(r, "PROGRAM_RECIPIENT")!.detail).to.match(/a program\b/);
      // the program's own upgrade authority is reported, for the human
      expect(r.programs[0].upgradeAuthority).to.not.equal(null);

      const pd = PublicKey.findProgramAddressSync([prog.toBuffer()], new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"))[0];
      expect(fact(await run(pd), "PROGRAM_RECIPIENT")!.detail).to.match(/ProgramData/);

      const native = key();
      chain.set(native, NATIVE_LOADER, Buffer.from("native"), { executable: true });
      expect(fact(await run(native), "PROGRAM_RECIPIENT")!.detail).to.match(/native program/);

      const v2 = key();
      putV2Program(chain, v2);
      expect((await run(v2)).level).to.equal("HIGH");
    });

    it("mints, token accounts and multisigs are HIGH, on either token program", async () => {
      const m = key();
      chain.set(m, TOKEN_PROGRAM, mintBytes());
      expect(fact(await run(m), "TOKEN_ACCOUNT_RECIPIENT")!.detail).to.match(/mint/);
      const t = key();
      chain.set(t, TOKEN_PROGRAM, tokenAccountBytes({ owner: key() }));
      expect(fact(await run(t), "TOKEN_ACCOUNT_RECIPIENT")!.detail).to.match(/token account/);
      const ms = key();
      chain.set(ms, TOKEN_PROGRAM, Buffer.alloc(355));
      expect(fact(await run(ms), "TOKEN_ACCOUNT_RECIPIENT")!.detail).to.match(/multisig/);
      const m22 = key();
      chain.set(m22, TOKEN_2022_PROGRAM, token2022MintBytes(mintBytes(), [tlv(9, Buffer.alloc(0))]));
      expect(fact(await run(m22), "TOKEN_ACCOUNT_RECIPIENT")!.detail).to.match(/mint/);
    });

    it("sysvars are HIGH; stake and vote accounts are HIGH but not guard-enforced", async () => {
      const sv = key();
      chain.set(sv, SYSVAR_OWNER, Buffer.alloc(40));
      expect(fact(await run(sv), "SYSVAR_RECIPIENT")!).to.include({ level: "HIGH", guardEnforced: true });
      const st = key();
      chain.set(st, STAKE_PROGRAM, Buffer.alloc(200));
      const r = await run(st);
      expect(fact(r, "NATIVE_PROGRAM_ACCOUNT")!.level).to.equal("HIGH");
      expect(fact(r, "NATIVE_PROGRAM_ACCOUNT")!.guardEnforced).to.equal(undefined);
    });
  });

  describe("program-controlled recipients", () => {
    it("a PDA with no account and no allow entry: controller unknown, MEDIUM", async () => {
      const pda = offCurve();
      const r = await run(pda);
      expect([r.level, r.kind, r.controller]).to.deep.equal(["MEDIUM", "pda", null]);
      expect(ids(r)).to.include.members(["OFF_CURVE_RECIPIENT", "UNKNOWN_CONTROLLER", "DESTINATION_MISSING"]);
    });

    it("a PDA allowlisted with a controller is judged by that controller", async () => {
      const program = key();
      putV3Program(chain, program, { authority: null, slot: 1n });
      const pda = offCurve("vault", program);
      chain.set(associatedTokenAddress(pda, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: pda }));
      guard.add("allow", pda, program);
      const r = await run(pda);
      expect([r.level, r.controller]).to.deep.equal(["LOW", program.toBase58()]);
      expect(ids(r)).to.include.members(["OFF_CURVE_RECIPIENT", "ALLOWLISTED", "IMMUTABLE_PROGRAM"]);
      expect(ids(r)).to.not.include("UNKNOWN_CONTROLLER");
    });

    it("data owned by an immutable program is LOW; by an upgradeable one, MEDIUM with the authority named", async () => {
      const immutable = key();
      putV3Program(chain, immutable, { authority: null });
      const a = key();
      chain.set(a, immutable, Buffer.alloc(16));
      chain.set(associatedTokenAddress(a, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: a }));
      const low = await run(a);
      expect([low.level, low.kind]).to.deep.equal(["LOW", "program-owned"]);
      expect(ids(low)).to.include.members(["PROGRAM_CONTROLLED", "IMMUTABLE_PROGRAM"]);

      const upgradeable = key();
      const authority = key();
      putV3Program(chain, upgradeable, { authority, slot: 42n });
      const b = key();
      chain.set(b, upgradeable, Buffer.alloc(16));
      chain.set(associatedTokenAddress(b, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: b }));
      const med = await run(b);
      expect(med.level).to.equal("MEDIUM");
      const up = fact(med, "UPGRADEABLE_PROGRAM") as any;
      expect(up.data).to.include({ upgradeAuthority: authority.toBase58(), deploySlot: 42 });
    });

    it("a program deployed within about an epoch is MEDIUM even without an authority", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null, slot: BigInt(chain.slot - 1000) });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      const r = await run(a);
      expect(ids(r)).to.include("RECENTLY_DEPLOYED");
      expect(fact(r, "RECENTLY_DEPLOYED")!.level).to.equal("MEDIUM");
    });

    it("an upgrade authority of all zeros counts as none", async () => {
      const p = key();
      putV3Program(chain, p, { authority: PublicKey.default });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      expect(ids(await run(a))).to.include("IMMUTABLE_PROGRAM");
    });

    it("a closed, retracted or missing controlling program is HIGH", async () => {
      // v3 program whose ProgramData is gone
      const closed = key();
      putV3Program(chain, closed, { authority: key() });
      chain.delete(PublicKey.findProgramAddressSync([closed.toBuffer()], new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"))[0]);
      const a = key();
      chain.set(a, closed, Buffer.alloc(8));
      expect(fact(await run(a), "CLOSED_PROGRAM")!.level).to.equal("HIGH");

      const retracted = key();
      putV4Program(chain, retracted, { status: 0, authority: key() });
      const b = key();
      chain.set(b, retracted, Buffer.alloc(8));
      expect(ids(await run(b))).to.include("CLOSED_PROGRAM");

      const ghost = key(); // an "owner" that is not a program at all
      const c = key();
      chain.set(c, ghost, Buffer.alloc(8));
      expect(ids(await run(c))).to.include("CLOSED_PROGRAM");
    });

    it("loader-v4: deployed is upgradeable, finalized is immutable", async () => {
      const dep = key();
      putV4Program(chain, dep, { status: 1, authority: key() });
      const a = key();
      chain.set(a, dep, Buffer.alloc(8));
      expect(ids(await run(a))).to.include("UPGRADEABLE_PROGRAM");
      const fin = key();
      putV4Program(chain, fin, { status: 2, authority: key() });
      const b = key();
      chain.set(b, fin, Buffer.alloc(8));
      expect(ids(await run(b))).to.include("IMMUTABLE_PROGRAM");
    });

    it("a program blocked on-chain is HIGH, whether it owns the data or is the allow entry's controller", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      guard.add("blockprog", p);
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      expect(fact(await run(a), "BLOCKED_PROGRAM")!.level).to.equal("HIGH");

      const pda = offCurve("x", p);
      guard.add("allow", pda, p);
      const r = await run(pda);
      expect(r.level).to.equal("HIGH");
      expect(ids(r)).to.include.members(["ALLOWLISTED", "BLOCKED_PROGRAM"]);
    });

    it("off the curve, the data owner is not taken as the controller: an immutable owner doesn't make it LOW", async () => {
      // Program Q (upgradeable) derives X and assigns X's data to immutable P.
      const p = key();
      putV3Program(chain, p, { authority: null });
      const q = key();
      putV3Program(chain, q, { authority: key() });
      const x = offCurve("x", q);
      chain.set(x, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(x, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: x }));
      const r = await run(x);
      expect([r.level, r.kind, r.controller]).to.deep.equal(["MEDIUM", "program-owned", null]);
      expect(fact(r, "UNKNOWN_CONTROLLER")!.detail).to.match(/need not be that program/);

      // Once the owner names Q in an allow entry, Q is what's judged, and a block on Q wins.
      guard.add("allow", x, q);
      const named = await run(x);
      expect(named.controller).to.equal(q.toBase58());
      expect(ids(named)).to.include("UPGRADEABLE_PROGRAM").and.not.include("UNKNOWN_CONTROLLER");
      guard.add("blockprog", q);
      expect((await run(x)).level).to.equal("HIGH");
    });

    it("an Address Lookup Table (a PDA its immutable program never signs for) is not LOW", async () => {
      const alt = new PublicKey("AddressLookupTab1e1111111111111111111111111");
      chain.set(alt, NATIVE_LOADER, Buffer.from("alt"), { executable: true });
      const table = offCurve("table", alt);
      chain.set(table, alt, Buffer.alloc(56));
      chain.set(associatedTokenAddress(table, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: table }));
      expect((await run(table)).level).to.equal("MEDIUM");
    });

    it("on the curve, a keypair signs for the USDC account, so no program is named as controller", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(a, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: a }));
      const r = await run(a);
      expect([r.level, r.controller]).to.deep.equal(["LOW", null]);
      expect(fact(r, "PROGRAM_CONTROLLED")!.detail).to.match(/a keypair signs/);
    });

    it("an account that names itself as its owner is not a program: CLOSED_PROGRAM, on or off the curve", async () => {
      const onCurve = key();
      chain.set(onCurve, onCurve, Buffer.alloc(8));
      const r1 = await run(onCurve);
      expect(r1.level).to.equal("HIGH");
      expect(ids(r1)).to.include("CLOSED_PROGRAM");

      const x = offCurve("self");
      chain.set(x, x, Buffer.alloc(8));
      expect(ids(await run(x))).to.include("CLOSED_PROGRAM");
    });

    it("a data-less, non-executable account owned by a loader is not a program", async () => {
      for (const loader of [BPF_LOADER_2, NATIVE_LOADER]) {
        const fake = key();
        chain.set(fake, loader, Buffer.alloc(0)); // anyone can createAccount(owner = loader)
        const a = key();
        chain.set(a, fake, Buffer.alloc(8));
        const r = await run(a);
        expect(ids(r), loader.toBase58()).to.include("CLOSED_PROGRAM").and.not.include("IMMUTABLE_PROGRAM");
      }
    });

    it("names a known program without lowering its risk", async () => {
      const memo = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
      putV2Program(chain, memo);
      const a = key();
      chain.set(a, memo, Buffer.alloc(8));
      const r = await run(a);
      expect(fact(r, "PROGRAM_CONTROLLED")!.detail).to.match(/Memo v2/);
      expect(r.programs[0].name).to.equal("Memo v2");
    });
  });

  describe("the destination USDC account", () => {
    it("owner reassigned away from the recipient is HIGH", async () => {
      const thief = key();
      const { wallet } = putWallet(chain, { ata: { owner: thief } });
      const r = await run(wallet);
      expect(r.level).to.equal("HIGH");
      expect((fact(r, "DESTINATION_OWNER_MISMATCH") as any).data.actualOwner).to.equal(thief.toBase58());
    });

    it("frozen is HIGH", async () => {
      const { wallet } = putWallet(chain, { ata: { state: 2 } });
      expect(fact(await run(wallet), "FROZEN_DESTINATION")!.level).to.equal("HIGH");
    });

    it("a delegate that can sweep the payment is HIGH; one that can't is MEDIUM; an unknown amount assumes the worst", async () => {
      const big = putWallet(chain, { ata: { delegate: key(), delegatedAmount: 2n ** 64n - 1n } });
      const unlimited = fact(await run(big.wallet), "DELEGATED_DESTINATION")!;
      expect(unlimited.level).to.equal("HIGH");
      expect(unlimited.detail).to.include("allowed to move an unlimited amount of USDC");
      const small = putWallet(chain, { ata: { delegate: key(), delegatedAmount: 5n } });
      const limited = fact(await run(small.wallet), "DELEGATED_DESTINATION")!;
      expect(limited.level).to.equal("MEDIUM");
      expect(limited.detail).to.include("allowed to move 0.000005 USDC");
      const unknownAmount = await inspect(small.wallet, { reader: chain, guard: guard.programId });
      expect(fact(unknownAmount, "DELEGATED_DESTINATION")!.level).to.equal("HIGH");
      const spent = putWallet(chain, { ata: { delegate: key(), delegatedAmount: 0n } });
      expect(ids(await run(spent.wallet))).to.not.include("DELEGATED_DESTINATION");
    });

    it("wrong mint, wrong program, uninitialized or malformed are HIGH", async () => {
      const wrongMint = putWallet(chain, { ata: { mint: key() } });
      expect(fact(await run(wrongMint.wallet), "BAD_DESTINATION")!.detail).to.match(/not USDC/);
      const uninit = putWallet(chain, { ata: { state: 0 } });
      expect(fact(await run(uninit.wallet), "BAD_DESTINATION")!.detail).to.match(/not initialized/);

      const w = key();
      chain.set(w, SYSTEM_PROGRAM);
      chain.set(associatedTokenAddress(w, USDC_MINT), TOKEN_2022_PROGRAM, tokenAccountBytes({ owner: w }));
      expect(fact(await run(w), "BAD_DESTINATION")!.detail).to.match(/Token-2022/);
      chain.set(associatedTokenAddress(w, USDC_MINT), TOKEN_PROGRAM, Buffer.alloc(170));
      expect(fact(await run(w), "BAD_DESTINATION")!.detail).to.match(/170 bytes/);
      const garbage = tokenAccountBytes({ owner: w });
      garbage[108] = 9;
      chain.set(associatedTokenAddress(w, USDC_MINT), TOKEN_PROGRAM, garbage);
      expect(fact(await run(w), "BAD_DESTINATION")!.detail).to.match(/could not be decoded/);
    });

    it("lamports a stranger sent to a wallet's ATA address read as 'missing', never as a bad destination", async () => {
      const { wallet, ata } = putWallet(chain, { ata: null });
      chain.set(ata, SYSTEM_PROGRAM); // 0 bytes, System-owned
      const r = await run(wallet);
      expect(r.level).to.equal("MEDIUM");
      expect(ids(r)).to.include("DESTINATION_MISSING").and.not.include("BAD_DESTINATION");
      expect(fact(r, "DESTINATION_MISSING")!.detail).to.match(/only lamports/);
      // An explicit (x402) destination holding only lamports is still not a token account.
      const other = key();
      chain.set(other, SYSTEM_PROGRAM);
      expect(ids(await run(wallet, { destination: other }))).to.include("BAD_DESTINATION");
    });

    it("a close authority other than the owner is noted, not escalated", async () => {
      const { wallet } = putWallet(chain, { ata: { closeAuthority: key() } });
      const r = await run(wallet);
      expect(r.level).to.equal("LOW");
      expect(ids(r)).to.include("DESTINATION_CLOSE_AUTHORITY");
    });

    it("an explicit destination that isn't the ATA is MEDIUM", async () => {
      const { wallet } = putWallet(chain);
      const other = key();
      chain.set(other, TOKEN_PROGRAM, tokenAccountBytes({ owner: wallet }));
      const r = await run(wallet, { destination: other });
      expect(r.level).to.equal("MEDIUM");
      expect(ids(r)).to.include("NON_CANONICAL_DESTINATION");
      expect(r.destination!.canonical).to.equal(false);
    });
  });

  describe("an asset other than USDC", () => {
    it("the look-alike: permanent delegate and 'USD Coin' metadata are HIGH, freeze authority MEDIUM", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      chain.set(
        mint,
        TOKEN_2022_PROGRAM,
        token2022MintBytes(mintBytes({ mintAuthority: key(), freezeAuthority: key() }), [
          tlv(12, key().toBuffer()),
          tlv(18, Buffer.concat([key().toBuffer(), mint.toBuffer()])),
          tlv(19, metadataValue({ mint, name: "USD Coin", symbol: "USDC" })),
        ])
      );
      const r = await run(wallet, { mint });
      expect(r.level).to.equal("HIGH");
      expect(ids(r)).to.include.members(["NOT_PINNED_ASSET", "PERMANENT_DELEGATE", "SPOOFED_METADATA", "FREEZE_AUTHORITY", "MINT_AUTHORITY"]);
      expect(fact(r, "FREEZE_AUTHORITY")!.level).to.equal("MEDIUM");
    });

    it("an unknown extension or an undecodable mint is HIGH, never a pass", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      chain.set(mint, TOKEN_2022_PROGRAM, token2022MintBytes(mintBytes(), [tlv(77, Buffer.alloc(2))]));
      expect(fact(await run(wallet, { mint }), "UNKNOWN_EXTENSION")!.level).to.equal("HIGH");
      chain.set(mint, TOKEN_2022_PROGRAM, Buffer.concat([mintBytes(), Buffer.alloc(3)]));
      expect(fact(await run(wallet, { mint }), "BAD_MINT")!.level).to.equal("HIGH");
      const nowhere = key();
      expect(fact(await run(wallet, { mint: nowhere }), "BAD_MINT")!.detail).to.match(/does not exist/);
    });

    it("grades hooks, fees, default-frozen, pause and metadata pointing elsewhere", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      const fee = Buffer.alloc(108);
      fee.writeUInt16LE(100, 106);
      const pausable = Buffer.concat([key().toBuffer(), Buffer.from([1])]);
      chain.set(
        mint,
        TOKEN_2022_PROGRAM,
        token2022MintBytes(mintBytes(), [
          tlv(14, Buffer.concat([key().toBuffer(), Buffer.alloc(32)])), // authority only
          tlv(1, fee),
          tlv(6, Buffer.from([2])),
          tlv(26, pausable),
          tlv(19, metadataValue({ mint: key(), name: "Coin", symbol: "CN" })),
        ])
      );
      const r = await run(wallet, { mint });
      expect(fact(r, "TRANSFER_HOOK")!.level).to.equal("LOW");
      expect(fact(r, "TRANSFER_FEE")!.level).to.equal("MEDIUM");
      expect(fact(r, "DEFAULT_FROZEN")!.level).to.equal("MEDIUM");
      expect(fact(r, "PAUSABLE")!.level).to.equal("MEDIUM");
      expect(fact(r, "METADATA_MISMATCH")!.level).to.equal("HIGH");
      expect(ids(r)).to.not.include("SPOOFED_METADATA");
    });

    it("strips hostile formatting from metadata before it is shown", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      chain.set(
        mint,
        TOKEN_2022_PROGRAM,
        token2022MintBytes(mintBytes(), [tlv(19, metadataValue({ mint, name: "USD‮C\x1b[2J oin", symbol: "U​SDC" }))])
      );
      const r = await run(wallet, { mint });
      const spoof = fact(r, "SPOOFED_METADATA") as any;
      expect(spoof.data.symbol).to.equal("USDC");
      expect(spoof.detail).to.not.match(/[‮​\x1b]/);
    });

    it("a clean mint that isn't USDC is still HIGH: Aegis only pays USDC", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      chain.set(mint, TOKEN_PROGRAM, mintBytes());
      const r = await run(wallet, { mint });
      expect(r.level).to.equal("HIGH");
      expect(fact(r, "NOT_PINNED_ASSET")!.level).to.equal("HIGH");
    });

    it("look-alike letters from other scripts are still 'USDC'", async () => {
      const { wallet } = putWallet(chain);
      for (const [name, symbol] of [
        ["USD Сoin", "UC"], // Cyrillic ES
        ["Coin", "USDС"], // Cyrillic ES
        ["Coin", "ＵＳＤＣ"], // fullwidth
        ["Coin", "UЅDC"], // Cyrillic DZE
      ]) {
        const mint = key();
        chain.set(mint, TOKEN_2022_PROGRAM, token2022MintBytes(mintBytes(), [tlv(19, metadataValue({ mint, name, symbol }))]));
        expect(ids(await run(wallet, { mint })), `${name} / ${symbol}`).to.include("SPOOFED_METADATA");
      }
    });

    it("metadata held in another account is flagged, since this lane can't read it", async () => {
      const { wallet } = putWallet(chain);
      const mint = key();
      chain.set(mint, TOKEN_2022_PROGRAM, token2022MintBytes(mintBytes(), [tlv(18, Buffer.concat([key().toBuffer(), key().toBuffer()]))]));
      expect(fact(await run(wallet, { mint }), "EXTERNAL_METADATA")!.level).to.equal("MEDIUM");
      // pointing at itself is the normal case
      chain.set(mint, TOKEN_2022_PROGRAM, token2022MintBytes(mintBytes(), [tlv(18, Buffer.concat([key().toBuffer(), mint.toBuffer()]))]));
      expect(ids(await run(wallet, { mint }))).to.not.include("EXTERNAL_METADATA");
    });

    it("the pinned USDC mint is not inspected as a foreign asset", async () => {
      const { wallet } = putWallet(chain);
      const r = await run(wallet, { mint: USDC_MINT });
      expect(ids(r)).to.not.include("NOT_PINNED_ASSET");
    });
  });

  describe("failing closed", () => {
    it("an RPC error is UNKNOWN, never 'no account, so a fresh wallet'", async () => {
      const { wallet } = putWallet(chain);
      chain.failing = true;
      const r = await run(wallet);
      expect(r.level).to.equal("UNKNOWN");
      expect(r.error).to.match(/429/);
      expect(r.reason).to.match(/Could not read/);
    });

    it("an RPC error in the second round (programs) is UNKNOWN too", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      const real = chain.getSlot.bind(chain);
      chain.getSlot = async () => {
        throw new Error("slot unavailable");
      };
      expect((await run(a)).level).to.equal("UNKNOWN");
      chain.getSlot = real;
    });

    it("a HIGH fact read in round 1 survives a round-2 failure", async () => {
      const failSlot = () => {
        chain.getSlot = async () => {
          throw new Error("slot unavailable");
        };
      };
      // the recipient is a program
      const prog = key();
      putV3Program(chain, prog, { authority: key() });
      failSlot();
      const r = await run(prog);
      expect(r.level).to.equal("HIGH");
      expect(r.reason).to.match(/Later reads failed: slot unavailable/);

      // a program-owned recipient whose USDC account is frozen
      const p = key();
      putV3Program(chain, p, { authority: null });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      chain.set(associatedTokenAddress(a, USDC_MINT), TOKEN_PROGRAM, tokenAccountBytes({ owner: a, state: 2 }));
      const f = await run(a);
      expect(f.level).to.equal("HIGH");
      expect(ids(f)).to.include("FROZEN_DESTINATION");
    });

    it("a guard id with no config account on this cluster is UNKNOWN, not 'no lists'", async () => {
      const { wallet } = putWallet(chain);
      const r = await inspect(wallet, { reader: chain, guard: key(), amount: 1n });
      expect(r.level).to.equal("UNKNOWN");
      expect(r.error).to.match(/no config account/);
    });

    it("lamports sent to an entry address don't make anyone a member", async () => {
      const { wallet } = putWallet(chain);
      chain.set(guard.pdas.entry("deny", wallet), SYSTEM_PROGRAM);
      const r = await run(wallet);
      expect(r.onchain!.denied).to.equal(false);
    });

    it("without a guard, the lists are skipped: onchain is null (aegisCheck says so)", async () => {
      const { wallet } = putWallet(chain);
      const r = await inspect(wallet, { reader: chain, guard: null, amount: 1n });
      expect(r.onchain).to.equal(null);
      expect(r.level).to.equal("LOW");
    });

    it("reads ProgramData with a 48-byte slice, never the whole ELF", async () => {
      const p = key();
      putV3Program(chain, p, { authority: null, elf: Buffer.alloc(100_000, 1) });
      const a = key();
      chain.set(a, p, Buffer.alloc(8));
      await run(a);
      const round2 = chain.calls.find((c) => c.slice);
      expect(round2!.slice).to.deep.equal({ offset: 0, length: 48 });
    });
  });
});

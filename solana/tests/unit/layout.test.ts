// The lanes read guard accounts without the Anchor client, so the hand-derived
// layouts are checked against what Anchor actually builds.
import { expect } from "chai";
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { PublicKey } from "@solana/web3.js";

import { GuardPdas, accountDiscriminator, readConfig, readEntry, readStats } from "../../src/guard/layout";
import { SYSTEM_PROGRAM, configBytes, entryBytes, key, statsBytes } from "./fixtures";

describe("unit: guard layouts", () => {
  const idlPath = join(__dirname, "..", "..", "target", "idl", "aegis_guard.json");

  it("account discriminators match the IDL", function () {
    if (!existsSync(idlPath)) this.skip();
    const idl = JSON.parse(readFileSync(idlPath, "utf8"));
    for (const a of idl.accounts) {
      expect([...accountDiscriminator(a.name)], a.name).to.deep.equal(a.discriminator);
    }
  });

  it("PDAs use the program's seeds", function () {
    if (!existsSync(idlPath)) this.skip();
    const idl = JSON.parse(readFileSync(idlPath, "utf8"));
    const pdas = new GuardPdas(new PublicKey(idl.address));
    const seed = (name: string) => Buffer.from(JSON.parse(idl.constants.find((c: any) => c.name === name).value));
    expect(pdas.config.equals(PublicKey.findProgramAddressSync([seed("CONFIG_SEED")], pdas.programId)[0])).to.equal(true);
    const who = key();
    for (const [kind, name] of [["agent", "AGENT_SEED"], ["deny", "DENY_SEED"], ["allow", "ALLOW_SEED"], ["blockprog", "BLOCKPROG_SEED"], ["reporter", "REPORTER_SEED"]] as const) {
      const expected = PublicKey.findProgramAddressSync([seed(name), pdas.config.toBuffer(), who.toBuffer()], pdas.programId)[0];
      expect(pdas.entry(kind, who).equals(expected), kind).to.equal(true);
    }
    expect(pdas.stats(who).equals(PublicKey.findProgramAddressSync([seed("PAID_SEED"), pdas.config.toBuffer(), who.toBuffer()], pdas.programId)[0])).to.equal(true);
    expect(pdas.audit.equals(PublicKey.findProgramAddressSync([seed("AUDIT_SEED"), pdas.config.toBuffer()], pdas.programId)[0])).to.equal(true);
  });

  it("an entry counts only when the guard owns it and it carries the discriminator", () => {
    const program = key();
    const controller = key();
    expect(readEntry({ owner: program, lamports: 1, executable: false, data: entryBytes(controller) }, program)!.controller!.equals(controller)).to.equal(true);
    expect(readEntry({ owner: program, lamports: 1, executable: false, data: entryBytes(null) }, program)!.controller).to.equal(null);
    expect(readEntry({ owner: SYSTEM_PROGRAM, lamports: 1, executable: false, data: entryBytes() }, program)).to.equal(null);
    expect(readEntry({ owner: program, lamports: 1, executable: false, data: statsBytes(1n, 1n, 1n) }, program)).to.equal(null);
    expect(readEntry(null, program)).to.equal(null);
  });

  it("reads stats and config", () => {
    const program = key();
    const s = readStats({ owner: program, lamports: 1, executable: false, data: statsBytes(2n, 5n, 7n) }, program);
    expect(s).to.deep.equal({ count: 2n, largest: 5n, total: 7n });
    const owner = key();
    const vault = key();
    const c = readConfig({ owner: program, lamports: 1, executable: false, data: configBytes({ owner, vault, dailyLimit: 9n }) }, program)!;
    expect(c.owner.equals(owner) && c.vault.equals(vault)).to.equal(true);
    expect(c.dailyLimit).to.equal(9n);
    expect(c.pendingOwner).to.equal(null);
  });

  it("reads config with a pending owner: every later field shifts by 32 bytes", () => {
    const program = key();
    const owner = key();
    const pending = key();
    const vault = key();
    const none = configBytes({ owner, vault, dailyLimit: 9n });
    // Option<Pubkey> = Some: tag 1 then 32 bytes, inserted after the owner.
    const some = Buffer.concat([none.subarray(0, 40), Buffer.from([1]), pending.toBuffer(), none.subarray(41)]);
    const c = readConfig({ owner: program, lamports: 1, executable: false, data: some }, program)!;
    expect(c.pendingOwner!.equals(pending)).to.equal(true);
    expect(c.vault.equals(vault)).to.equal(true);
    expect(c.dailyLimit).to.equal(9n);
  });
});

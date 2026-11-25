// Codes are cheap to add and expensive to be wrong about. Pinned here: a code
// that stops being raised, a guard error that isn't mapped, and a code that is
// guessed instead of recognized.
import { expect } from "chai";
import { readdirSync, readFileSync, statSync, existsSync } from "fs";
import { join } from "path";

import {
  GUARD_ERRORS_NOT_REFUSALS,
  REFUSAL,
  REFUSAL_CODES,
  guardErrorCode,
  guardFailureCode,
  guardReasonCode,
  isRefusalCode,
} from "../../src/refusals";

const ROOT = join(__dirname, "..", "..");

function sourceFiles(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sourceFiles(path, out);
    else if (name.endsWith(".ts")) out.push(path);
  }
  return out;
}

// Codes are raised through the REFUSAL object, so only `REFUSAL.X` counts as a
// use, in every file. A bare word would also match the inspection lane's fact
// ids (FROZEN_DESTINATION, ...), and then deleting a code's only real use, its
// GUARD_ERRORS mapping, would leave this test green.
function usesOf(code: string, files: string[]): number {
  const pattern = new RegExp(`REFUSAL\\.${code}\\b`, "g");
  return files.reduce((total, file) => total + (readFileSync(file, "utf8").match(pattern) ?? []).length, 0);
}

const files = () => [...sourceFiles(join(ROOT, "src")), ...sourceFiles(join(ROOT, "scripts"))];

describe("unit: refusal codes", () => {
  it("the vocabulary is a frozen set of keys that equal their values", () => {
    expect(Object.isFrozen(REFUSAL)).to.equal(true);
    for (const [k, v] of Object.entries(REFUSAL)) expect(k).to.equal(v);
    expect(REFUSAL_CODES.length).to.equal(Object.keys(REFUSAL).length);
    expect(isRefusalCode("DENYLISTED")).to.equal(true);
    expect(isRefusalCode("denylisted")).to.equal(false);
    expect(isRefusalCode(null)).to.equal(false);
  });

  it("every code is actually raised somewhere", () => {
    for (const code of REFUSAL_CODES) expect(usesOf(code, files()), `${code} is defined but never raised`).to.be.at.least(1);
  });

  it("the dead-code check can actually fail", () => {
    expect(usesOf("NEVER_RAISED_ANYWHERE", files())).to.equal(0);
  });

  describe("against the built IDL", () => {
    const idlPath = join(ROOT, "target", "idl", "aegis_guard.json");
    before(function () {
      if (!existsSync(idlPath)) this.skip();
    });

    it("every aegis_guard error is mapped to a code or deliberately excluded", () => {
      const idl = JSON.parse(readFileSync(idlPath, "utf8"));
      for (const e of idl.errors) {
        const code = guardErrorCode(e.name);
        expect(code === null ? GUARD_ERRORS_NOT_REFUSALS.includes(e.name) : code !== "UNKNOWN", e.name).to.equal(true);
      }
      for (const name of GUARD_ERRORS_NOT_REFUSALS) {
        expect(idl.errors.map((e: any) => e.name), `stale exclusion ${name}`).to.include(name);
      }
    });

    it("every `assess` reason maps to a code, and only `clear` to none", () => {
      const idl = JSON.parse(readFileSync(idlPath, "utf8"));
      const reason = idl.types.find((t: any) => t.name === "Reason");
      for (const v of reason.type.variants) {
        const camel = v.name.charAt(0).toLowerCase() + v.name.slice(1);
        const code = guardReasonCode(camel);
        if (v.name === "Clear") expect(code).to.equal(null);
        else expect(code, v.name).to.not.equal("UNKNOWN").and.to.not.equal(null);
      }
    });
  });

  it("unknown stays unknown: no fuzzy matches", () => {
    expect(guardErrorCode("NotAgentt")).to.equal("UNKNOWN");
    expect(guardErrorCode("ConstraintSeeds")).to.equal("UNKNOWN");
    expect(guardErrorCode(undefined)).to.equal("UNKNOWN");
    expect(guardReasonCode("deny")).to.equal("UNKNOWN");
    expect(guardReasonCode("clear")).to.equal(null);
    expect(guardReasonCode("dailyCap")).to.equal("DAILY_CAP");
  });

  it("reads a failed payment's code from an AnchorError, its logs, or the token program", () => {
    const prog = "CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6";
    const anchorErr = { error: { errorCode: { code: "Denylisted" } }, program: { toString: () => prog } };
    expect(guardFailureCode(prog, anchorErr)).to.equal("DENYLISTED");
    const foreign = { error: { errorCode: { code: "Denylisted" } }, program: { toString: () => "Other111" } };
    expect(guardFailureCode(prog, foreign)).to.equal("UNKNOWN");
    const logs = [
      `Program ${prog} invoke [1]`,
      "Program log: AnchorError occurred. Error Code: DelegatedDestination. Error Number: 6013. Error Message: x.",
      `Program ${prog} failed: custom program error: 0x177d`,
    ];
    expect(guardFailureCode(prog, null, logs)).to.equal("DELEGATED_DESTINATION");
    const tokenFail = [`Program ${prog} invoke [1]`, "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA failed: custom program error: 0x1"];
    expect(guardFailureCode(prog, null, tokenFail)).to.equal("TRANSFER_FAILED");
    expect(guardFailureCode(prog, new Error("blockhash not found"))).to.equal("UNKNOWN");
  });

  it("another program's AnchorError is never read as ours, named or in the logs", () => {
    const prog = "CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6";
    const other = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";
    const foreignLogs = [
      `Program ${other} invoke [1]`,
      "Program log: AnchorError thrown in programs/other/src/lib.rs:42. Error Code: Denylisted. Error Number: 6004. Error Message: nope.",
      `Program ${other} failed: custom program error: 0x1774`,
    ];
    const named = { error: { errorCode: { code: "Denylisted" } }, program: { toString: () => other }, logs: foreignLogs };
    expect(guardFailureCode(prog, named)).to.equal("UNKNOWN");
    expect(guardFailureCode(prog, null, foreignLogs)).to.equal("UNKNOWN");
    // Our program calling into another that fails with an AnchorError: still not ours.
    const nested = [`Program ${prog} invoke [1]`, `Program ${other} invoke [2]`, ...foreignLogs.slice(1), `Program ${prog} failed: x`];
    expect(guardFailureCode(prog, null, nested)).to.equal("UNKNOWN");
    // And ours after a nested call that succeeded is ours.
    const after = [
      `Program ${prog} invoke [1]`,
      `Program ${other} invoke [2]`,
      `Program ${other} success`,
      "Program log: AnchorError occurred. Error Code: DailyCap. Error Number: 6014. Error Message: x.",
      `Program ${prog} failed: x`,
    ];
    expect(guardFailureCode(prog, null, after)).to.equal("DAILY_CAP");
  });
});

// One process per beat keeps the owner key out of the drain and x402 agent runs.
import { spawnSync } from "child_process";
import { readFileSync } from "fs";
import { resolve } from "path";
import { Connection, Keypair } from "@solana/web3.js";

import { guardProgramId, rpcUrl } from "../src/config";
import {
  badMintX402,
  delegatedRecipient,
  goodRecipient,
  injectedDrain,
  killSwitch,
} from "../src/demo/beats";
import { DemoBeat, DemoKeys } from "../src/demo/common";
import { formatDemo } from "../src/demo/format";

const beats: DemoBeat[] = ["good", "delegated", "bad-mint", "drain", "kill"];
const file = (name: string) => resolve("keys", `${name}.json`);
const key = (name: string) =>
  Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(file(name), "utf8")))
  );
const publicKey = (name: string) => key(name).publicKey;

async function main() {
  const beat = process.argv[2] as DemoBeat | "all" | undefined;
  if (!beat || (beat !== "all" && !beats.includes(beat)))
    throw new Error(`usage: yarn demo <${[...beats, "all"].join("|")}>`);
  if (beat === "all") {
    for (const one of beats) {
      const child = spawnSync(
        "sh",
        [
          "scripts/with-toolchain.sh",
          "node",
          "-r",
          "ts-node/register/transpile-only",
          "scripts/demo.ts",
          one,
        ],
        { stdio: "inherit", cwd: resolve("."), env: process.env }
      );
      if (child.error) throw child.error;
      if (child.status !== 0) {
        process.exitCode = child.status ?? 1;
        return;
      }
    }
    return;
  }
  if (!process.env.AEGIS_PROGRAM_ID)
    throw new Error("set AEGIS_PROGRAM_ID to the deployed aegis_guard id");
  const programId = guardProgramId();
  if (!programId) throw new Error("AEGIS_PROGRAM_ID is not a valid program id");
  const connection = new Connection(rpcUrl(), "confirmed");
  const keys: DemoKeys = {};
  if (
    beat === "good" ||
    beat === "drain" ||
    beat === "kill" ||
    beat === "bad-mint"
  )
    keys.agent = key("agent");
  if (beat === "delegated" || beat === "kill") keys.owner = key("owner");
  if (beat === "delegated") keys.agent = key("agent");
  if (beat === "good" || beat === "kill") keys.good = publicKey("demo-good");
  if (beat === "delegated" || beat === "drain")
    keys.villain = publicKey("demo-villain");
  if (beat === "bad-mint") {
    keys.reporter = key("demo-reporter");
    keys.float = key("demo-float");
    keys.merchant = key("demo-merchant");
    keys.badMint = publicKey("demo-bad-mint");
  }
  const opts = { programId };
  const run = {
    good: goodRecipient,
    delegated: delegatedRecipient,
    "bad-mint": badMintX402,
    drain: injectedDrain,
    kill: killSwitch,
  }[beat];
  const result = await run(connection, keys, opts);
  console.log(await formatDemo(connection, result));
  if (!result.ok) process.exitCode = 1;
}

main().catch((err) => {
  console.error(
    `demo stopped: ${err instanceof Error ? err.message : String(err)}`
  );
  process.exitCode = 1;
});

// Recover the demo agent after an interrupted kill-switch beat. This command
// checks only the agent entry; setup's funding checks must not block recovery.
import { readFileSync } from "fs";
import { resolve } from "path";
import { Connection, Keypair } from "@solana/web3.js";

import { DEVNET_GENESIS_HASH, guardProgramId, rpcUrl } from "../src/config";
import { explorerUrl } from "../src/demo/common";
import { restoreAgentEntry } from "../src/demo/recovery";
import { GuardClient } from "../src/guard/client";

const key = (name: string) =>
  Keypair.fromSecretKey(
    Uint8Array.from(
      JSON.parse(readFileSync(resolve("keys", `${name}.json`), "utf8"))
    )
  );

async function main() {
  if (!process.env.AEGIS_PROGRAM_ID)
    throw new Error("set AEGIS_PROGRAM_ID to the deployed aegis_guard id");
  const programId = guardProgramId();
  if (!programId) throw new Error("AEGIS_PROGRAM_ID is not a valid program id");
  const connection = new Connection(rpcUrl(), "confirmed");
  const genesis = await connection.getGenesisHash();
  const host = new URL(connection.rpcEndpoint).hostname;
  if (
    genesis !== DEVNET_GENESIS_HASH &&
    !["127.0.0.1", "localhost", "::1"].includes(host)
  )
    throw new Error(
      "the RPC is neither Solana devnet nor a local validator; refusing restore writes"
    );

  const owner = key("owner");
  const agent = key("agent").publicKey;
  const client = new GuardClient(connection, programId, owner.publicKey);
  const restored = await restoreAgentEntry(client, owner, agent);
  if (restored.outcome?.signature)
    console.log(
      `restore transaction (${
        restored.outcome.ok
          ? "succeeded"
          : restored.outcome.landed === true
          ? "failed"
          : "unknown"
      }): ${await explorerUrl(connection, restored.outcome.signature)}`
    );
  console.log(
    restored.alreadyPresent
      ? "skip restore: the agent entry is already present"
      : "the agent entry is present after recovery"
  );
}

main().catch((err) => {
  console.error(
    `agent restore stopped: ${err instanceof Error ? err.message : String(err)}`
  );
  process.exitCode = 1;
});

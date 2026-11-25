// Read state first. On localnet, create fresh demo accounts and mint only the
// validator's test USDC. On devnet, say what SOL and faucet USDC are needed.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { Connection, Keypair } from "@solana/web3.js";

import { DEVNET_GENESIS_HASH, guardProgramId, rpcUrl } from "../src/config";
import { explorerUrl } from "../src/demo/common";
import { DemoSetupKeys, ensureDemoSetup } from "../src/demo/setup";

const keysDir = resolve("keys");
const file = (name: string) => resolve(keysDir, `${name}.json`);
const load = (name: string) =>
  Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(file(name), "utf8")))
  );
function fresh(name: string): Keypair {
  if (existsSync(file(name))) return load(name);
  const pair = Keypair.generate();
  writeFileSync(file(name), JSON.stringify(Array.from(pair.secretKey)), {
    mode: 0o600,
    flag: "wx",
  });
  console.log(`created fresh key: keys/${name}.json`);
  return pair;
}

async function main() {
  if (!process.env.AEGIS_PROGRAM_ID)
    throw new Error("set AEGIS_PROGRAM_ID to the deployed aegis_guard id");
  const programId = guardProgramId();
  if (!programId) throw new Error("AEGIS_PROGRAM_ID is not a valid program id");
  mkdirSync(keysDir, { recursive: true });
  const connection = new Connection(rpcUrl(), "confirmed");
  const genesis = await connection.getGenesisHash();
  const devnet = genesis === DEVNET_GENESIS_HASH;
  const host = new URL(connection.rpcEndpoint).hostname;
  const localnet = !devnet && ["127.0.0.1", "localhost", "::1"].includes(host);
  if (!devnet && !localnet)
    throw new Error(
      "the RPC is neither Solana devnet nor a local validator; refusing setup writes"
    );
  const keys: DemoSetupKeys = {
    deployer: load("deployer"),
    owner: load("owner"),
    agent: load("agent"),
    payer: fresh("demo-payer"),
    reporter: fresh("demo-reporter"),
    good: fresh("demo-good"),
    villain: fresh("demo-villain"),
    attacker: fresh("demo-attacker"),
    float: fresh("demo-float"),
    merchant: fresh("demo-merchant"),
    badMint: fresh("demo-bad-mint"),
    ...(localnet
      ? {
          mintAuthority: Keypair.fromSecretKey(
            Uint8Array.from(
              JSON.parse(
                readFileSync("tests/fixtures/mint-authority.json", "utf8")
              )
            )
          ),
        }
      : {}),
  };
  const funded: [string, Keypair, number][] = [
    ["deployer", keys.deployer!, 2],
    ["owner", keys.owner, 1],
    ["agent", keys.agent, 1],
    ["demo-payer", keys.payer, 3],
    ["demo-reporter", keys.reporter, 0.5],
    ["demo-merchant", keys.merchant, 0.5],
  ];
  const missingSol: string[] = [];
  for (const [name, keypair, targetSol] of funded) {
    const balance = await connection.getBalance(keypair.publicKey, "confirmed");
    const needed = Math.ceil(targetSol * 1_000_000_000) - balance;
    if (needed <= 0) {
      console.log(`skip ${name}: enough SOL`);
      continue;
    }
    if (devnet) {
      missingSol.push(
        `${name} ${keypair.publicKey.toBase58()}: at least ${(
          needed / 1_000_000_000
        ).toFixed(3)} more SOL`
      );
      continue;
    }
    const signature = await connection.requestAirdrop(
      keypair.publicKey,
      needed
    );
    const latest = await connection.getLatestBlockhash("confirmed");
    await connection.confirmTransaction({ signature, ...latest }, "confirmed");
    console.log(`funded ${name}: ${await explorerUrl(connection, signature)}`);
  }
  if (missingSol.length) {
    console.log("Fund these keys with devnet SOL, then rerun setup:");
    for (const line of missingSol) console.log(`  ${line}`);
    process.exitCode = 1;
    return;
  }
  if ((await connection.getBalance(keys.float.publicKey, "confirmed")) !== 0)
    throw new Error(
      "the x402 float wallet has SOL; use a fresh zero-SOL float key before the demo"
    );
  const result = await ensureDemoSetup(connection, keys, {
    programId,
    localnet,
  });
  for (const action of result.actions)
    console.log(
      `${action.state === "done" ? "did" : "skip"} ${action.label}${
        action.signature
          ? `: ${await explorerUrl(connection, action.signature)}`
          : ""
      }`
    );
  for (const line of result.needed) console.log(line);
  if (!result.ready) process.exitCode = 1;
  else
    console.log(
      `demo ready on ${
        devnet ? "devnet" : "localnet"
      }; vault ${result.vault.toBase58()}`
    );
}

main().catch((err) => {
  console.error(
    `demo setup stopped: ${err instanceof Error ? err.message : String(err)}`
  );
  process.exitCode = 1;
});

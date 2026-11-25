import { expect } from "chai";
import { Connection, Keypair, PublicKey, SYSVAR_CLOCK_PUBKEY } from "@solana/web3.js";

import {
  DEVNET_GENESIS_HASH,
  SYSVAR_OWNER,
  SYSTEM_PROGRAM,
} from "../../src/config";
import { demoResult, explorerUrl } from "../../src/demo/common";
import { formatDemo } from "../../src/demo/format";
import { restoreAgentEntry } from "../../src/demo/recovery";
import { checkDemoAllowance } from "../../src/demo/setup";

describe("unit: demo output", () => {
  it("links transactions to devnet or the custom local RPC", async () => {
    const devnet = {
      rpcEndpoint: "https://example.invalid",
      getGenesisHash: async () => DEVNET_GENESIS_HASH,
    } as any;
    let reads = 0;
    const local = {
      rpcEndpoint: "http://127.0.0.1:8899",
      getGenesisHash: async () => (reads++, "local-genesis"),
    } as any;
    expect(await explorerUrl(devnet, "sig")).to.equal(
      "https://explorer.solana.com/tx/sig?cluster=devnet"
    );
    expect(await explorerUrl(local, "sig")).to.equal(
      "https://explorer.solana.com/tx/sig?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899"
    );
    const result = demoResult("good");
    result.ok = true;
    result.transactions.push({
      label: "guarded payment",
      signature: "sig",
      outcome: "succeeded",
    });
    expect(await formatDemo(local, result)).to.include("The model was skipped");
    expect(reads).to.equal(1);
  });

  it("describes the drain balance that was measured, even if the expected block failed", async () => {
    const connection = {
      rpcEndpoint: "http://127.0.0.1:8899",
      getGenesisHash: async () => "local-genesis",
    } as Connection;
    const result = demoResult("drain");
    result.balances.vaultBefore = 20_000_000n;
    result.balances.vaultAfter = 19_000_000n;
    result.transactions.push({ label: "injected guarded_pay", signature: "sig", outcome: "succeeded" });
    const changed = await formatDemo(connection, result);
    expect(changed).to.include("Vault moved from 20 to 19 USDC");
    expect(changed).not.to.include("Vault stayed");
    result.balances.vaultAfter = 20_000_000n;
    result.transactions[0].outcome = "failed";
    const unchanged = await formatDemo(connection, result);
    expect(unchanged).to.include("Vault stayed at 20 USDC; the failed transaction is public");
  });
});

describe("unit: demo setup allowance", () => {
  const cfg = {
    dailyLimit: 3_000_000n,
    currentDay: 5n,
    spentToday: 2_500_000n,
  };
  const clock = (now: bigint, owner = SYSVAR_OWNER, size = 40) => {
    const data = Buffer.alloc(size);
    if (size >= 40) data.writeBigInt64LE(now, 32);
    return {
      getAccountInfo: async (address: PublicKey, commitment: string) => {
        expect(address.equals(SYSVAR_CLOCK_PUBKEY)).to.equal(true);
        expect(commitment).to.equal("confirmed");
        return { owner, data };
      },
    } as unknown as Connection;
  };
  const refused = async (check: Promise<unknown>, reason: RegExp) => {
    try {
      await check;
      throw new Error("expected setup to refuse the allowance");
    } catch (err) {
      expect((err as Error).message).to.match(reason);
    }
  };

  it("refuses when too much of today's daily cap has been spent", async () => {
    await refused(
      checkDemoAllowance(clock(5n * 86_400n), cfg),
      /only 0.5 USDC of remaining daily allowance/
    );
  });

  it("yesterday's spend does not consume today's allowance", async () => {
    expect(await checkDemoAllowance(clock(6n * 86_400n), cfg)).to.equal(
      3_000_000n
    );
  });

  it("keeps spend when the clock goes back, including a negative timestamp", async () => {
    await refused(
      checkDemoAllowance(clock(4n * 86_400n), cfg),
      /remaining daily allowance/
    );
    await refused(
      checkDemoAllowance(clock(-1n), { ...cfg, currentDay: -1n }),
      /remaining daily allowance/
    );
  });

  it("refuses an unreadable or malformed chain clock", async () => {
    await refused(
      checkDemoAllowance(
        { getAccountInfo: async () => null } as unknown as Connection,
        cfg
      ),
      /chain clock could not be read/
    );
    await refused(
      checkDemoAllowance(clock(6n * 86_400n, SYSTEM_PROGRAM), cfg),
      /chain clock could not be read/
    );
    await refused(
      checkDemoAllowance(clock(6n * 86_400n, SYSVAR_OWNER, 32), cfg),
      /chain clock could not be read/
    );
  });
});

describe("unit: demo agent recovery", () => {
  const owner = Keypair.generate();
  const agent = Keypair.generate().publicKey;
  const send = { ok: true, signature: "sig", landed: true, code: null, error: null, logs: [] };

  it("skips the write if the entry is already present", async () => {
    let writes = 0;
    const client = {
      entry: async () => ({ member: true, controller: null }),
      addEntry: async () => { writes++; return send; },
    } as any;
    expect(await restoreAgentEntry(client, owner, agent)).to.deep.equal({ alreadyPresent: true, outcome: null });
    expect(writes).to.equal(0);
  });

  it("adds a missing entry and confirms it by reading the chain", async () => {
    let present = false;
    const client = {
      entry: async () => ({ member: present, controller: null }),
      addEntry: async () => { present = true; return send; },
    } as any;
    expect(await restoreAgentEntry(client, owner, agent)).to.deep.equal({ alreadyPresent: false, outcome: send });
  });

  it("checks again after an initial read error, even if the write then fails", async () => {
    let reads = 0;
    const client = {
      entry: async () => {
        if (++reads === 1) throw new Error("RPC unavailable");
        return { member: true, controller: null };
      },
      addEntry: async () => { throw new Error("entry already exists"); },
    } as any;
    expect(await restoreAgentEntry(client, owner, agent)).to.deep.equal({ alreadyPresent: false, outcome: null });
    expect(reads).to.equal(2);
  });

  it("reports failure when the entry is still missing", async () => {
    const client = {
      entry: async () => ({ member: false, controller: null }),
      addEntry: async () => ({ ...send, ok: false, error: "RPC refused" }),
    } as any;
    try {
      await restoreAgentEntry(client, owner, agent);
      throw new Error("expected recovery to fail");
    } catch (err) {
      expect((err as Error).message).to.match(/still missing after restore: RPC refused/);
    }
  });
});

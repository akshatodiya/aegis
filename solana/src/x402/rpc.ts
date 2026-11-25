// The reads the x402 rail makes, behind one interface so tests can hand it a
// scripted chain. A throw from here means "could not read", never "no".
//
// Simulation goes over raw JSON-RPC: web3.js 1.x drops the balance fields
// (pre/postBalances, pre/postTokenBalances) that the signer compares, and those
// are the point of simulating.
import { Connection } from "@solana/web3.js";

import { AccountReader, connectionReader } from "../chain/reader";

export interface TokenBalance {
  accountIndex: number;
  mint: string;
  /** Missing on old RPCs; the signer refuses rather than guess. */
  owner: string | null;
  /** Base units, as a decimal string. */
  amount: string;
}

export interface SimulationResult {
  err: unknown;
  unitsConsumed: number | null;
  preBalances: number[] | null;
  postBalances: number[] | null;
  preTokenBalances: TokenBalance[] | null;
  postTokenBalances: TokenBalance[] | null;
  logs: string[] | null;
}

export interface SvmRpc {
  reader: AccountReader;
  genesisHash(): Promise<string>;
  latestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: number }>;
  isBlockhashValid(blockhash: string): Promise<boolean>;
  /** Simulates the wire transaction as is: no signature check, blockhash not replaced. */
  simulate(wire: Uint8Array): Promise<SimulationResult>;
}

export function connectionRpc(connection: Connection): SvmRpc {
  return {
    reader: connectionReader(connection),
    genesisHash: () => connection.getGenesisHash(),
    latestBlockhash: () => connection.getLatestBlockhash("confirmed"),
    async isBlockhashValid(blockhash) {
      const { value } = await connection.isBlockhashValid(blockhash, { commitment: "confirmed" });
      return value === true;
    },
    async simulate(wire) {
      const res = await fetch(connection.rpcEndpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "simulateTransaction",
          params: [
            Buffer.from(wire).toString("base64"),
            { encoding: "base64", sigVerify: false, replaceRecentBlockhash: false, commitment: "confirmed" },
          ],
        }),
      });
      if (!res.ok) throw new Error(`simulateTransaction: HTTP ${res.status}`);
      const body: any = await res.json();
      if (body?.error) throw new Error(`simulateTransaction: ${body.error.message ?? JSON.stringify(body.error)}`);
      return parseSimulation(body?.result?.value);
    },
  };
}

const numbers = (v: unknown): number[] | null => (Array.isArray(v) && v.every((n) => typeof n === "number") ? (v as number[]) : null);

function tokenBalances(v: unknown): TokenBalance[] | null {
  if (!Array.isArray(v)) return null;
  const out: TokenBalance[] = [];
  for (const b of v) {
    const amount = b?.uiTokenAmount?.amount;
    if (typeof b?.accountIndex !== "number" || typeof b?.mint !== "string" || typeof amount !== "string" || !/^\d+$/.test(amount)) return null;
    out.push({ accountIndex: b.accountIndex, mint: b.mint, owner: typeof b.owner === "string" ? b.owner : null, amount });
  }
  return out;
}

export function parseSimulation(value: any): SimulationResult {
  if (!value || typeof value !== "object") throw new Error("simulateTransaction returned no result");
  if (!Object.prototype.hasOwnProperty.call(value, "err") || value.err === undefined) throw new Error("simulateTransaction returned no err field");
  return {
    err: value.err,
    unitsConsumed: typeof value.unitsConsumed === "number" ? value.unitsConsumed : null,
    preBalances: numbers(value.preBalances),
    postBalances: numbers(value.postBalances),
    preTokenBalances: tokenBalances(value.preTokenBalances),
    postTokenBalances: tokenBalances(value.postTokenBalances),
    logs: Array.isArray(value.logs) ? value.logs.map(String) : null,
  };
}

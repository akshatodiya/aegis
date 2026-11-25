import { Connection, Keypair, PublicKey } from "@solana/web3.js";

import { DEVNET_GENESIS_HASH } from "../config";
import { RefusalCode } from "../refusals";

export type DemoBeat = "good" | "delegated" | "bad-mint" | "drain" | "kill";

export interface DemoKeys {
  owner?: Keypair;
  agent?: Keypair;
  payer?: Keypair;
  reporter?: Keypair;
  float?: Keypair;
  merchant?: Keypair;
  good?: PublicKey;
  villain?: PublicKey;
  badMint?: PublicKey;
}

export interface DemoOptions {
  programId: PublicKey;
  /** Every payment is a bigint of USDC base units. */
  amount?: bigint;
  floatTarget?: bigint;
}

export interface DemoTransaction {
  label: string;
  signature: string;
  outcome: "succeeded" | "failed" | "unknown";
}

export interface DemoVerdict {
  label: string;
  decision: "PAY" | "BLOCK" | "ASK_HUMAN" | "REVIEW";
  code: RefusalCode | null;
}

export interface DemoFact {
  id: string;
  level: string;
  detail: string;
}

export interface DemoResult {
  beat: DemoBeat;
  ok: boolean;
  transactions: DemoTransaction[];
  verdicts: DemoVerdict[];
  facts: DemoFact[];
  /** Named USDC balances in base units, before and after the beat. */
  balances: Record<string, bigint>;
  /** Machine-readable details such as a bridge write or an audit receipt. */
  details: Record<string, string | boolean | bigint | null>;
  notes: string[];
}

export function demoResult(beat: DemoBeat): DemoResult {
  return {
    beat,
    ok: false,
    transactions: [],
    verdicts: [],
    facts: [],
    balances: {},
    details: {},
    notes: [
      "The model was skipped; these verdicts use chain facts and fixed rules.",
    ],
  };
}

export function needKey<T>(key: T | undefined, name: string): T {
  if (!key)
    throw new Error(
      `the ${name} key is needed for this demo beat; run yarn demo:setup first`
    );
  return key;
}

const explorerClusters = new WeakMap<Connection, Promise<string>>();

/** Explorer accepts a custom RPC URL for a local validator. */
export async function explorerUrl(
  connection: Connection,
  signature: string
): Promise<string> {
  let cluster = explorerClusters.get(connection);
  if (!cluster) {
    cluster = connection
      .getGenesisHash()
      .then((genesis) =>
        genesis === DEVNET_GENESIS_HASH
          ? "cluster=devnet"
          : `cluster=custom&customUrl=${encodeURIComponent(
              connection.rpcEndpoint
            )}`
      );
    explorerClusters.set(connection, cluster);
    cluster.catch(() => explorerClusters.delete(connection));
  }
  return `https://explorer.solana.com/tx/${signature}?${await cluster}`;
}

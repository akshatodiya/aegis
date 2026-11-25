// The guard's addresses and account layouts, without the Anchor client. The
// lanes read entries and stats with these, so the x402 signer can run the same
// policy without loading a provider or a key.
import { createHash } from "crypto";
import { PublicKey } from "@solana/web3.js";

import { ATA_PROGRAM, TOKEN_PROGRAM } from "../config";
import type { RawAccount } from "../chain/reader";

export type EntryKind = "agent" | "deny" | "allow" | "blockprog" | "reporter";

/** Anchor's account discriminator: sha256("account:<Name>")[..8]. */
export function accountDiscriminator(name: string): Buffer {
  return createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);
}

const ENTRY_DISC = accountDiscriminator("Entry");
const STATS_DISC = accountDiscriminator("Stats");
const CONFIG_DISC = accountDiscriminator("Config");

export class GuardPdas {
  readonly config: PublicKey;
  readonly audit: PublicKey;

  constructor(readonly programId: PublicKey) {
    this.config = this.pda([Buffer.from("config")]);
    this.audit = this.pda([Buffer.from("audit"), this.config.toBuffer()]);
  }

  private pda(seeds: Buffer[]): PublicKey {
    return PublicKey.findProgramAddressSync(seeds, this.programId)[0];
  }

  entry(kind: EntryKind, key: PublicKey): PublicKey {
    return this.pda([Buffer.from(kind), this.config.toBuffer(), key.toBuffer()]);
  }

  stats(recipient: PublicKey): PublicKey {
    return this.pda([Buffer.from("paid"), this.config.toBuffer(), recipient.toBuffer()]);
  }

  vault(mint: PublicKey): PublicKey {
    return associatedTokenAddress(this.config, mint);
  }
}

/** ATA(owner, mint) under the classic Token program. No curve check: callers classify the owner first. */
export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram = TOKEN_PROGRAM): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    ATA_PROGRAM
  )[0];
}

export interface EntryData {
  controller: PublicKey | null;
}

/**
 * The guard's membership rule, off-chain: an entry counts only when the
 * account is owned by the guard program and carries the Entry discriminator.
 * Lamports alone (anyone can send them) are absence.
 */
export function readEntry(account: RawAccount | null, programId: PublicKey): EntryData | null {
  if (!account || !account.owner.equals(programId)) return null;
  if (account.data.length < 8 + 32 + 1 || !account.data.subarray(0, 8).equals(ENTRY_DISC)) return null;
  const controller = new PublicKey(account.data.subarray(8, 40));
  return { controller: controller.equals(PublicKey.default) ? null : controller };
}

export interface StatsData {
  count: bigint;
  largest: bigint;
  total: bigint;
}

/**
 * null = never paid through this guard. Only guarded_pay can create a program
 * account at this PDA, so an account owned by anyone else is lamports someone
 * sent, which is still "never". A guard-owned account with the wrong layout is
 * an error: the caller reports "unknown", never "never".
 */
export function readStats(account: RawAccount | null, programId: PublicKey): StatsData | null {
  if (!account || !account.owner.equals(programId)) return null;
  if (account.data.length < 8 + 24 + 1 || !account.data.subarray(0, 8).equals(STATS_DISC)) {
    throw new Error("stats account has an unexpected layout");
  }
  return {
    count: account.data.readBigUInt64LE(8),
    largest: account.data.readBigUInt64LE(16),
    total: account.data.readBigUInt64LE(24),
  };
}

export interface ConfigData {
  owner: PublicKey;
  pendingOwner: PublicKey | null;
  mint: PublicKey;
  vault: PublicKey;
  dailyLimit: bigint;
  currentDay: bigint;
  spentToday: bigint;
  paused: boolean;
  payCount: bigint;
}

export function readConfig(account: RawAccount | null, programId: PublicKey): ConfigData | null {
  if (!account || !account.owner.equals(programId) || !account.data.subarray(0, 8).equals(CONFIG_DISC)) return null;
  const d = account.data;
  let at = 8;
  const owner = new PublicKey(d.subarray(at, at + 32));
  at += 32;
  let pendingOwner: PublicKey | null = null;
  if (d[at] === 1) {
    pendingOwner = new PublicKey(d.subarray(at + 1, at + 33));
    at += 33;
  } else {
    at += 1;
  }
  const mint = new PublicKey(d.subarray(at, at + 32));
  at += 32;
  const vault = new PublicKey(d.subarray(at, at + 32));
  at += 32;
  const dailyLimit = d.readBigUInt64LE(at);
  const currentDay = d.readBigInt64LE(at + 8);
  const spentToday = d.readBigUInt64LE(at + 16);
  const paused = d[at + 24] === 1;
  const payCount = d.readBigUInt64LE(at + 25);
  return { owner, pendingOwner, mint, vault, dailyLimit, currentDay, spentToday, paused, payCount };
}

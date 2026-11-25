// Byte builders and an in-memory chain for the lane unit tests. Layouts follow
// src/chain/decode.ts, which follows the programs' own state definitions.
import { Keypair, PublicKey } from "@solana/web3.js";

import type { AccountReader, RawAccount, Slice } from "../../src/chain/reader";
import {
  BPF_LOADER_2,
  BPF_LOADER_UPGRADEABLE,
  LOADER_V4,
  SYSTEM_PROGRAM,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  USDC_MINT,
} from "../../src/config";
import { accountDiscriminator, associatedTokenAddress, GuardPdas } from "../../src/guard/layout";

export const key = () => Keypair.generate().publicKey;
export const offCurve = (seed = "pda", program = key()) => PublicKey.findProgramAddressSync([Buffer.from(seed)], program)[0];

export class FakeChain implements AccountReader {
  readonly accounts = new Map<string, RawAccount>();
  slot = 10_000_000;
  failing = false;
  calls: { keys: string[]; slice?: Slice }[] = [];

  set(address: PublicKey, owner: PublicKey, data: Buffer = Buffer.alloc(0), extra: Partial<RawAccount> = {}) {
    this.accounts.set(address.toBase58(), { owner, data, lamports: 1_000_000, executable: false, ...extra });
    return this;
  }

  delete(address: PublicKey) {
    this.accounts.delete(address.toBase58());
  }

  async getAccounts(keys: PublicKey[], slice?: Slice): Promise<(RawAccount | null)[]> {
    this.calls.push({ keys: keys.map((k) => k.toBase58()), slice });
    if (this.failing) throw new Error("429 Too Many Requests");
    return keys.map((k) => {
      const a = this.accounts.get(k.toBase58());
      if (!a) return null;
      return slice ? { ...a, data: a.data.subarray(slice.offset, slice.offset + slice.length) } : a;
    });
  }

  async getSlot(): Promise<number> {
    if (this.failing) throw new Error("429 Too Many Requests");
    return this.slot;
  }
}

function cOption(k: PublicKey | null): Buffer {
  const b = Buffer.alloc(36);
  if (k) {
    b.writeUInt32LE(1, 0);
    k.toBuffer().copy(b, 4);
  }
  return b;
}

export function tokenAccountBytes(o: {
  mint?: PublicKey;
  owner: PublicKey;
  amount?: bigint;
  delegate?: PublicKey | null;
  delegatedAmount?: bigint;
  state?: 0 | 1 | 2;
  closeAuthority?: PublicKey | null;
}): Buffer {
  const b = Buffer.alloc(165);
  (o.mint ?? USDC_MINT).toBuffer().copy(b, 0);
  o.owner.toBuffer().copy(b, 32);
  b.writeBigUInt64LE(o.amount ?? 0n, 64);
  cOption(o.delegate ?? null).copy(b, 72);
  b[108] = o.state ?? 1;
  b.writeBigUInt64LE(o.delegatedAmount ?? 0n, 121);
  cOption(o.closeAuthority ?? null).copy(b, 129);
  return b;
}

export function mintBytes(o: { mintAuthority?: PublicKey | null; supply?: bigint; decimals?: number; freezeAuthority?: PublicKey | null; initialized?: boolean } = {}): Buffer {
  const b = Buffer.alloc(82);
  cOption(o.mintAuthority ?? null).copy(b, 0);
  b.writeBigUInt64LE(o.supply ?? 0n, 36);
  b[44] = o.decimals ?? 6;
  b[45] = o.initialized === false ? 0 : 1;
  cOption(o.freezeAuthority ?? null).copy(b, 46);
  return b;
}

export function tlv(type: number, value: Buffer): Buffer {
  const head = Buffer.alloc(4);
  head.writeUInt16LE(type, 0);
  head.writeUInt16LE(value.length, 2);
  return Buffer.concat([head, value]);
}

/** A Token-2022 mint: base, zero padding to 165, account type 1, then TLV entries. */
export function token2022MintBytes(base: Buffer, entries: Buffer[], trailingZeros = 0): Buffer {
  return Buffer.concat([base, Buffer.alloc(165 - 82), Buffer.from([1]), ...entries, Buffer.alloc(trailingZeros)]);
}

export function borshString(s: string): Buffer {
  const body = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length, 0);
  return Buffer.concat([len, body]);
}

export function metadataValue(o: { updateAuthority?: PublicKey | null; mint: PublicKey; name: string; symbol: string; uri?: string }): Buffer {
  return Buffer.concat([
    (o.updateAuthority ?? PublicKey.default).toBuffer(),
    o.mint.toBuffer(),
    borshString(o.name),
    borshString(o.symbol),
    borshString(o.uri ?? ""),
    Buffer.alloc(4), // additional_metadata: empty vec
  ]);
}

export function programDataAddress(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([programId.toBuffer()], BPF_LOADER_UPGRADEABLE)[0];
}

/** Puts a loader-v3 program on the fake chain; authority null = immutable. */
export function putV3Program(chain: FakeChain, programId: PublicKey, o: { authority: PublicKey | null; slot?: bigint; elf?: Buffer }) {
  const prog = Buffer.alloc(36);
  prog.writeUInt32LE(2, 0);
  programDataAddress(programId).toBuffer().copy(prog, 4);
  chain.set(programId, BPF_LOADER_UPGRADEABLE, prog, { executable: true });
  const header = Buffer.alloc(45);
  header.writeUInt32LE(3, 0);
  header.writeBigUInt64LE(o.slot ?? 1n, 4);
  if (o.authority) {
    header[12] = 1;
    o.authority.toBuffer().copy(header, 13);
  }
  chain.set(programDataAddress(programId), BPF_LOADER_UPGRADEABLE, Buffer.concat([header, o.elf ?? Buffer.alloc(64, 7)]));
}

export function putV2Program(chain: FakeChain, programId: PublicKey) {
  chain.set(programId, BPF_LOADER_2, Buffer.alloc(64, 7), { executable: true });
}

export function putV4Program(chain: FakeChain, programId: PublicKey, o: { status: 0 | 1 | 2; authority: PublicKey; slot?: bigint }) {
  const b = Buffer.alloc(48 + 16);
  b.writeBigUInt64LE(o.slot ?? 1n, 0);
  o.authority.toBuffer().copy(b, 8);
  b.writeBigUInt64LE(BigInt(o.status), 40);
  chain.set(programId, LOADER_V4, b, { executable: true });
}

export function entryBytes(controller: PublicKey | null = null): Buffer {
  return Buffer.concat([accountDiscriminator("Entry"), (controller ?? PublicKey.default).toBuffer(), Buffer.from([255])]);
}

export function statsBytes(count: bigint, largest: bigint, total: bigint): Buffer {
  const b = Buffer.alloc(8 + 24 + 1);
  accountDiscriminator("Stats").copy(b, 0);
  b.writeBigUInt64LE(count, 8);
  b.writeBigUInt64LE(largest, 16);
  b.writeBigUInt64LE(total, 24);
  return b;
}

export function configBytes(o: { owner: PublicKey; mint?: PublicKey; vault: PublicKey; dailyLimit?: bigint }): Buffer {
  const b = Buffer.alloc(8 + 32 + 1 + 32 + 32 + 8 + 8 + 8 + 1 + 8 + 1);
  let at = 0;
  accountDiscriminator("Config").copy(b, at);
  at += 8;
  o.owner.toBuffer().copy(b, at);
  at += 32;
  b[at] = 0; // pending_owner: None
  at += 1;
  (o.mint ?? USDC_MINT).toBuffer().copy(b, at);
  at += 32;
  o.vault.toBuffer().copy(b, at);
  at += 32;
  b.writeBigUInt64LE(o.dailyLimit ?? 1_000_000_000n, at);
  return b;
}

/** A guard on the fake chain: config account, vault address, and helpers to add entries. */
export function putGuard(chain: FakeChain, programId = key()) {
  const pdas = new GuardPdas(programId);
  const vault = pdas.vault(USDC_MINT);
  chain.set(pdas.config, programId, configBytes({ owner: key(), vault }));
  return {
    programId,
    pdas,
    vault,
    add(kind: "agent" | "deny" | "allow" | "blockprog" | "reporter", k: PublicKey, controller: PublicKey | null = null) {
      chain.set(pdas.entry(kind, k), programId, entryBytes(controller));
    },
    paid(recipient: PublicKey, count: bigint, largest: bigint, total: bigint) {
      chain.set(pdas.stats(recipient), programId, statsBytes(count, largest, total));
    },
  };
}

/** A wallet (System-owned, on-curve) with a clean USDC ATA. */
export function putWallet(chain: FakeChain, o: { lamports?: boolean; ata?: Partial<Parameters<typeof tokenAccountBytes>[0]> | null } = {}) {
  const wallet = key();
  if (o.lamports !== false) chain.set(wallet, SYSTEM_PROGRAM);
  const ata = associatedTokenAddress(wallet, USDC_MINT);
  if (o.ata !== null) chain.set(ata, TOKEN_PROGRAM, tokenAccountBytes({ owner: wallet, ...(o.ata ?? {}) }));
  return { wallet, ata };
}

export { TOKEN_2022_PROGRAM, TOKEN_PROGRAM, SYSTEM_PROGRAM, USDC_MINT };

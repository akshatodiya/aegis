// Byte decoders for the accounts the lanes read. Hand-written on purpose: the
// library decoders either don't check the owner program or throw on an
// extension they don't know, and the lane needs both of those to be explicit
// decisions. Every decoder throws DecodeError on anything it can't account for
// byte for byte; callers turn that into a refusal, never into a pass.
import { PublicKey } from "@solana/web3.js";

export class DecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecodeError";
  }
}

const ZERO_KEY = new PublicKey(Buffer.alloc(32));

function need(data: Buffer, len: number, what: string) {
  if (data.length < len) throw new DecodeError(`${what}: expected at least ${len} bytes, got ${data.length}`);
}

function key(data: Buffer, at: number): PublicKey {
  return new PublicKey(data.subarray(at, at + 32));
}

/** A 32-byte key where all zeros means "none" (Token-2022's OptionalNonZeroPubkey). */
function optionalKey(data: Buffer, at: number): PublicKey | null {
  const k = key(data, at);
  return k.equals(ZERO_KEY) ? null : k;
}

/** SPL COption<Pubkey>: u32 tag (0 none, 1 some), then 32 bytes. */
function cOptionKey(data: Buffer, at: number, what: string): PublicKey | null {
  const tag = data.readUInt32LE(at);
  if (tag === 0) return null;
  if (tag === 1) return key(data, at + 4);
  throw new DecodeError(`${what}: bad COption tag ${tag}`);
}

// ---- SPL token accounts ----

export const TOKEN_ACCOUNT_LEN = 165;
export const MINT_LEN = 82;
export const MULTISIG_LEN = 355;
const ACCOUNT_TYPE_OFFSET = 165;
const ACCOUNT_TYPE_MINT = 1;

export type TokenAccountState = "uninitialized" | "initialized" | "frozen";

export interface TokenAccountData {
  mint: PublicKey;
  owner: PublicKey;
  amount: bigint;
  delegate: PublicKey | null;
  state: TokenAccountState;
  isNative: boolean;
  delegatedAmount: bigint;
  closeAuthority: PublicKey | null;
}

/** The 165-byte base shared by classic Token and Token-2022 accounts. */
export function decodeTokenAccount(data: Buffer): TokenAccountData {
  need(data, TOKEN_ACCOUNT_LEN, "token account");
  const stateByte = data[108];
  const state: TokenAccountState | undefined = (["uninitialized", "initialized", "frozen"] as const)[stateByte];
  if (!state) throw new DecodeError(`token account: bad state ${stateByte}`);
  const nativeTag = data.readUInt32LE(109);
  if (nativeTag > 1) throw new DecodeError(`token account: bad is_native tag ${nativeTag}`);
  return {
    mint: key(data, 0),
    owner: key(data, 32),
    amount: data.readBigUInt64LE(64),
    delegate: cOptionKey(data, 72, "token account delegate"),
    state,
    isNative: nativeTag === 1,
    delegatedAmount: data.readBigUInt64LE(121),
    closeAuthority: cOptionKey(data, 129, "token account close authority"),
  };
}

// ---- mints ----

export interface MintData {
  mintAuthority: PublicKey | null;
  supply: bigint;
  decimals: number;
  isInitialized: boolean;
  freezeAuthority: PublicKey | null;
  /** Token-2022 extensions, in account order. Empty for a classic mint. */
  extensions: Extension[];
}

export function decodeMintBase(data: Buffer): Omit<MintData, "extensions"> {
  need(data, MINT_LEN, "mint");
  const init = data[45];
  if (init > 1) throw new DecodeError(`mint: bad is_initialized ${init}`);
  return {
    mintAuthority: cOptionKey(data, 0, "mint authority"),
    supply: data.readBigUInt64LE(36),
    decimals: data[44],
    isInitialized: init === 1,
    freezeAuthority: cOptionKey(data, 46, "freeze authority"),
  };
}

/** A classic SPL Token mint is exactly 82 bytes. */
export function decodeClassicMint(data: Buffer): MintData {
  if (data.length !== MINT_LEN) throw new DecodeError(`classic mint: expected ${MINT_LEN} bytes, got ${data.length}`);
  return { ...decodeMintBase(data), extensions: [] };
}

/** A Token-2022 mint: 82 bytes, or the base padded to 165, an account-type byte, then TLV extensions. */
export function decodeToken2022Mint(data: Buffer): MintData {
  const base = decodeMintBase(data);
  if (data.length === MINT_LEN) return { ...base, extensions: [] };
  need(data, ACCOUNT_TYPE_OFFSET + 1, "token-2022 mint");
  if (data.length === MULTISIG_LEN) throw new DecodeError("token-2022 mint: account has multisig length");
  for (let i = MINT_LEN; i < ACCOUNT_TYPE_OFFSET; i++) {
    if (data[i] !== 0) throw new DecodeError("token-2022 mint: non-zero padding before the account type");
  }
  if (data[ACCOUNT_TYPE_OFFSET] !== ACCOUNT_TYPE_MINT) {
    throw new DecodeError(`token-2022 mint: account type ${data[ACCOUNT_TYPE_OFFSET]} is not a mint`);
  }
  return { ...base, extensions: parseTlv(data.subarray(ACCOUNT_TYPE_OFFSET + 1)).map(decodeExtension) };
}

// ---- Token-2022 TLV extensions ----

export const EXTENSION_NAMES: Record<number, string> = {
  1: "TransferFeeConfig",
  2: "TransferFeeAmount",
  3: "MintCloseAuthority",
  4: "ConfidentialTransferMint",
  5: "ConfidentialTransferAccount",
  6: "DefaultAccountState",
  7: "ImmutableOwner",
  8: "MemoTransfer",
  9: "NonTransferable",
  10: "InterestBearingConfig",
  11: "CpiGuard",
  12: "PermanentDelegate",
  13: "NonTransferableAccount",
  14: "TransferHook",
  15: "TransferHookAccount",
  16: "ConfidentialTransferFeeConfig",
  17: "ConfidentialTransferFeeAmount",
  18: "MetadataPointer",
  19: "TokenMetadata",
  20: "GroupPointer",
  21: "TokenGroup",
  22: "GroupMemberPointer",
  23: "TokenGroupMember",
  24: "ConfidentialMintBurn",
  25: "ScaledUiAmountConfig",
  26: "PausableConfig",
  27: "PausableAccount",
  28: "PermissionedBurn",
};

export interface RawTlv {
  type: number;
  value: Buffer;
}

/**
 * Walks type (u16) / length (u16) / value entries. A zero type with zero length
 * is trailing padding, and everything after it must be zero too. An entry that
 * runs past the end is an error, not a truncated read.
 */
export function parseTlv(tlv: Buffer): RawTlv[] {
  const out: RawTlv[] = [];
  let i = 0;
  while (i < tlv.length) {
    if (tlv.length - i < 4) {
      if (tlv.subarray(i).some((b) => b !== 0)) throw new DecodeError("tlv: trailing bytes that are not an entry");
      break;
    }
    const type = tlv.readUInt16LE(i);
    const len = tlv.readUInt16LE(i + 2);
    if (type === 0) {
      if (len !== 0 || tlv.subarray(i).some((b) => b !== 0)) {
        throw new DecodeError("tlv: an uninitialized entry followed by data");
      }
      break;
    }
    if (i + 4 + len > tlv.length) throw new DecodeError(`tlv: entry ${type} runs past the end of the account`);
    out.push({ type, value: tlv.subarray(i + 4, i + 4 + len) });
    i += 4 + len;
  }
  return out;
}

export type Extension =
  | { type: number; name: "Unknown" }
  | { type: 1; name: "TransferFeeConfig"; configAuthority: PublicKey | null; withdrawAuthority: PublicKey | null; olderBps: number; newerBps: number; olderEpoch: bigint; newerEpoch: bigint; newerMaximumFee: bigint }
  | { type: 3; name: "MintCloseAuthority"; authority: PublicKey | null }
  | { type: 6; name: "DefaultAccountState"; state: TokenAccountState }
  | { type: 9; name: "NonTransferable" }
  | { type: 10; name: "InterestBearingConfig"; rateAuthority: PublicKey | null; currentRate: number }
  | { type: 12; name: "PermanentDelegate"; delegate: PublicKey | null }
  | { type: 14; name: "TransferHook"; authority: PublicKey | null; programId: PublicKey | null }
  | { type: 18; name: "MetadataPointer"; authority: PublicKey | null; metadataAddress: PublicKey | null }
  | { type: 19; name: "TokenMetadata"; updateAuthority: PublicKey | null; mint: PublicKey; tokenName: string; symbol: string; uri: string }
  | { type: 25; name: "ScaledUiAmountConfig"; authority: PublicKey | null }
  | { type: 26; name: "PausableConfig"; authority: PublicKey | null; paused: boolean }
  | { type: number; name: string; known: true };

function fixedLen(value: Buffer, len: number, name: string) {
  if (value.length !== len) throw new DecodeError(`${name}: expected ${len} bytes, got ${value.length}`);
}

function borshString(value: Buffer, at: number, what: string): [string, number] {
  need(value, at + 4, what);
  const len = value.readUInt32LE(at);
  if (at + 4 + len > value.length) throw new DecodeError(`${what}: string runs past the end`);
  return [value.subarray(at + 4, at + 4 + len).toString("utf8"), at + 4 + len];
}

export function decodeExtension({ type, value }: RawTlv): Extension {
  const name = EXTENSION_NAMES[type];
  if (!name) return { type, name: "Unknown" };
  switch (type) {
    case 1: {
      fixedLen(value, 108, name);
      return {
        type,
        name: "TransferFeeConfig",
        configAuthority: optionalKey(value, 0),
        withdrawAuthority: optionalKey(value, 32),
        olderEpoch: value.readBigUInt64LE(72),
        olderBps: value.readUInt16LE(88),
        newerEpoch: value.readBigUInt64LE(90),
        newerMaximumFee: value.readBigUInt64LE(98),
        newerBps: value.readUInt16LE(106),
      };
    }
    case 3:
      fixedLen(value, 32, name);
      return { type, name: "MintCloseAuthority", authority: optionalKey(value, 0) };
    case 6: {
      fixedLen(value, 1, name);
      const state = (["uninitialized", "initialized", "frozen"] as const)[value[0]];
      if (!state) throw new DecodeError(`DefaultAccountState: bad state ${value[0]}`);
      return { type, name: "DefaultAccountState", state };
    }
    case 9:
      fixedLen(value, 0, name);
      return { type, name: "NonTransferable" };
    case 10:
      fixedLen(value, 52, name);
      return { type, name: "InterestBearingConfig", rateAuthority: optionalKey(value, 0), currentRate: value.readInt16LE(50) };
    case 12:
      fixedLen(value, 32, name);
      return { type, name: "PermanentDelegate", delegate: optionalKey(value, 0) };
    case 14:
      fixedLen(value, 64, name);
      return { type, name: "TransferHook", authority: optionalKey(value, 0), programId: optionalKey(value, 32) };
    case 18:
      fixedLen(value, 64, name);
      return { type, name: "MetadataPointer", authority: optionalKey(value, 0), metadataAddress: optionalKey(value, 32) };
    case 19: {
      need(value, 64, name);
      const [tokenName, a] = borshString(value, 64, "TokenMetadata name");
      const [symbol, b] = borshString(value, a, "TokenMetadata symbol");
      const [uri] = borshString(value, b, "TokenMetadata uri");
      return { type, name: "TokenMetadata", updateAuthority: optionalKey(value, 0), mint: key(value, 32), tokenName, symbol, uri };
    }
    case 25:
      fixedLen(value, 56, name);
      return { type, name: "ScaledUiAmountConfig", authority: optionalKey(value, 0) };
    case 26:
      fixedLen(value, 33, name);
      if (value[32] > 1) throw new DecodeError(`PausableConfig: bad bool ${value[32]}`);
      return { type, name: "PausableConfig", authority: optionalKey(value, 0), paused: value[32] === 1 };
    default:
      return { type, name, known: true };
  }
}

// ---- loaders ----

export type LoaderV3State =
  | { kind: "uninitialized" }
  | { kind: "buffer"; authority: PublicKey | null }
  | { kind: "program"; programData: PublicKey }
  | { kind: "programData"; slot: bigint; authority: PublicKey | null };

/** bincode UpgradeableLoaderState: u32 tag, then the variant. Only the header is needed. */
export function decodeLoaderV3(data: Buffer): LoaderV3State {
  need(data, 4, "loader-v3 account");
  const tag = data.readUInt32LE(0);
  switch (tag) {
    case 0:
      return { kind: "uninitialized" };
    case 1: {
      need(data, 5, "loader-v3 buffer");
      const some = data[4];
      if (some > 1) throw new DecodeError(`loader-v3 buffer: bad option tag ${some}`);
      if (some === 1) need(data, 37, "loader-v3 buffer");
      return { kind: "buffer", authority: some === 1 ? key(data, 5) : null };
    }
    case 2:
      need(data, 36, "loader-v3 program");
      return { kind: "program", programData: key(data, 4) };
    case 3: {
      need(data, 13, "loader-v3 programdata");
      const some = data[12];
      if (some > 1) throw new DecodeError(`loader-v3 programdata: bad option tag ${some}`);
      if (some === 1) need(data, 45, "loader-v3 programdata");
      return { kind: "programData", slot: data.readBigUInt64LE(4), authority: some === 1 ? key(data, 13) : null };
    }
    default:
      throw new DecodeError(`loader-v3: unknown state tag ${tag}`);
  }
}

export const PROGRAM_DATA_HEADER_LEN = 45;

export type LoaderV4Status = "retracted" | "deployed" | "finalized";

export interface LoaderV4State {
  slot: bigint;
  /** The authority while deployed or retracted; the next version once finalized. */
  authorityOrNext: PublicKey;
  status: LoaderV4Status;
}

export const LOADER_V4_HEADER_LEN = 48;

export function decodeLoaderV4(data: Buffer): LoaderV4State {
  need(data, LOADER_V4_HEADER_LEN, "loader-v4 program");
  const statusNum = data.readBigUInt64LE(40);
  const status = (["retracted", "deployed", "finalized"] as const)[Number(statusNum)];
  if (statusNum > 2n || !status) throw new DecodeError(`loader-v4: unknown status ${statusNum}`);
  return { slot: data.readBigUInt64LE(0), authorityOrNext: key(data, 8), status };
}

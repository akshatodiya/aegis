// Known programs and mints, so the lane can name them instead of treating them
// as strangers. The same idea as the EVM build's CIRCLE_SYSTEM table: naming a
// program says what its trust rests on; it never zeroes a risk. None of these is
// ever written to the guard's `blockprog` list, because blocking one would
// refuse ordinary accounts that happen to be owned by it.
import { PublicKey } from "@solana/web3.js";

export interface KnownProgram {
  name: string;
  note: string;
}

const NATIVE = "a native program";
const IMMUTABLE = "deployed without an upgrade authority";
const UPGRADEABLE = "upgradeable by its publisher, so its logic can change";

const PROGRAMS: Record<string, KnownProgram> = {
  "11111111111111111111111111111111": { name: "System Program", note: NATIVE },
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: { name: "SPL Token", note: IMMUTABLE },
  TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb: { name: "Token-2022", note: UPGRADEABLE },
  ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL: { name: "Associated Token Account", note: IMMUTABLE },
  MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr: { name: "Memo v2", note: IMMUTABLE },
  Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo: { name: "Memo v1", note: IMMUTABLE },
  ComputeBudget111111111111111111111111111111: { name: "Compute Budget", note: NATIVE },
  AddressLookupTab1e1111111111111111111111111: { name: "Address Lookup Table", note: IMMUTABLE },
  BPFLoaderUpgradeab1e11111111111111111111111: { name: "BPF Loader (upgradeable)", note: NATIVE },
  BPFLoader2111111111111111111111111111111111: { name: "BPF Loader 2", note: NATIVE },
  BPFLoader1111111111111111111111111111111111: { name: "BPF Loader 1", note: NATIVE },
  LoaderV411111111111111111111111111111111111: { name: "Loader v4", note: NATIVE },
  NativeLoader1111111111111111111111111111111: { name: "Native Loader", note: NATIVE },
  Stake11111111111111111111111111111111111111: { name: "Stake Program", note: NATIVE },
  Vote111111111111111111111111111111111111111: { name: "Vote Program", note: NATIVE },
  Config1111111111111111111111111111111111111: { name: "Config Program", note: NATIVE },
  Sysvar1111111111111111111111111111111111111: { name: "Sysvar owner", note: NATIVE },
  SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf: { name: "Squads v4", note: UPGRADEABLE },
  CCTPV2Sm4AdWt5296sk4P66VBZ7bEhcARwFaaS9YPbeC: { name: "CCTP v2 MessageTransmitter (Circle)", note: UPGRADEABLE },
  CCTPV2vPZJS2u2BBsUoscuikbYjnpFmbFsvVuJdgUMQe: { name: "CCTP v2 TokenMessengerMinter (Circle)", note: UPGRADEABLE },
  CCTPmbSD7gX1bxKPAmg77w8oFzNFpaQiQUWD43TKaecd: { name: "CCTP v1 MessageTransmitter (Circle)", note: UPGRADEABLE },
  CCTPiPYPc6AsJuwueEnWgSgucamXDZwBd53dQ11YiKX3: { name: "CCTP v1 TokenMessengerMinter (Circle)", note: UPGRADEABLE },
  metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s: { name: "Metaplex Token Metadata", note: UPGRADEABLE },
};

export function knownProgram(id: PublicKey | string): KnownProgram | null {
  return PROGRAMS[id.toString()] ?? null;
}

export interface KnownMint {
  name: string;
  /** Issuer powers (freeze, permanent delegate) are expected here: issuer trust, not a finding. */
  issuer: string;
}

// PYUSD and USDG are mainnet Token-2022 mints that carry a permanent delegate by
// design. Listed so a regulated stablecoin reads as "issuer trust" rather than a
// honeypot. Their addresses are from on-chain metadata, not the issuers' docs.
const MINTS: Record<string, KnownMint> = {
  "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU": { name: "USDC (devnet)", issuer: "Circle" },
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: { name: "USDC", issuer: "Circle" },
  "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo": { name: "PYUSD", issuer: "Paxos" },
  "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH": { name: "USDG", issuer: "Paxos" },
};

export function knownMint(id: PublicKey | string): KnownMint | null {
  return MINTS[id.toString()] ?? null;
}

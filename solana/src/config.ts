// Addresses and constants shared by the lanes, the guard client and (later) the
// x402 rail. Nothing here reads a key. RPC and program id come from the
// environment so the same code runs against the local validator and devnet.
import { PublicKey } from "@solana/web3.js";

export const USDC_DECIMALS = 6;

/** Devnet USDC, a classic SPL Token mint. Tests put a local mint at the same address. */
export const USDC_MINT = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

/** `getGenesisHash` on devnet; the CAIP-2 id is its first 32 characters. */
export const DEVNET_GENESIS_HASH = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/** The x402 network id for a cluster: `solana:` + the first 32 characters of its genesis hash. */
export function caip2(genesisHash: string): string {
  return `solana:${genesisHash.slice(0, 32)}`;
}

/** The only network the x402 rail pays on, unless a test pins its own validator's. */
export const X402_NETWORK = caip2(DEVNET_GENESIS_HASH);

export const SYSTEM_PROGRAM = new PublicKey("11111111111111111111111111111111");
export const TOKEN_PROGRAM = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const TOKEN_2022_PROGRAM = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
export const ATA_PROGRAM = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
export const MEMO_PROGRAM = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
export const COMPUTE_BUDGET_PROGRAM = new PublicKey("ComputeBudget111111111111111111111111111111");

export const BPF_LOADER_UPGRADEABLE = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
export const BPF_LOADER_2 = new PublicKey("BPFLoader2111111111111111111111111111111111");
export const BPF_LOADER_1 = new PublicKey("BPFLoader1111111111111111111111111111111111");
export const LOADER_V4 = new PublicKey("LoaderV411111111111111111111111111111111111");
export const NATIVE_LOADER = new PublicKey("NativeLoader1111111111111111111111111111111");
export const LOADERS = [BPF_LOADER_UPGRADEABLE, BPF_LOADER_2, BPF_LOADER_1, LOADER_V4, NATIVE_LOADER];

/** Owner of every sysvar account. */
export const SYSVAR_OWNER = new PublicKey("Sysvar1111111111111111111111111111111111111");
/** Native programs whose accounts hold stake, votes or config, not payments. */
export const VOTE_PROGRAM = new PublicKey("Vote111111111111111111111111111111111111111");
export const STAKE_PROGRAM = new PublicKey("Stake11111111111111111111111111111111111111");
export const CONFIG_PROGRAM = new PublicKey("Config1111111111111111111111111111111111111");

/** Tokens sent here can be burned by anyone. */
export const INCINERATOR = new PublicKey("1nc1nerator11111111111111111111111111111111");

/** Rough length of one epoch in slots. A program deployed more recently than this is "new". */
export const RECENT_DEPLOY_SLOTS = 432_000;

/** The RPC the lanes read from. Use a paid endpoint for the demo: devnet's public one rate-limits. */
export function rpcUrl(): string {
  return (
    process.env.AEGIS_RPC_URL ||
    process.env.ANCHOR_PROVIDER_URL ||
    "https://api.devnet.solana.com"
  );
}

/**
 * The deployed aegis_guard program. Read from the environment, else from the
 * built IDL. Returns null when neither is available, so lanes that need the
 * guard can say "not configured" instead of guessing.
 */
export function guardProgramId(): PublicKey | null {
  const fromEnv = process.env.AEGIS_PROGRAM_ID;
  if (fromEnv) return new PublicKey(fromEnv);
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const idl = require("../target/idl/aegis_guard.json");
    return new PublicKey(idl.address);
  } catch {
    return null;
  }
}

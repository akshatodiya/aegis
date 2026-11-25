// The service catalog: the x402 half of the reputation lane.
//
// Before the agent pays a 402, the wrapper asks two questions the signer alone
// can't answer, because they need off-wire context: did this service's origin
// ask for its listed payTo, and is the amount the price that service posts? An
// unlisted origin or payTo is unknown; an amount over the posted price is a
// bait-and-switch (or a decimals mistake: 0.01 becoming 10,000). This stands in
// for a live marketplace lookup; only the source of truth would change.
//
// Prices are USDC base units, the unit PaymentRequirements use. Addresses are
// base58 and compared exactly: they have no case to fold, and two strings that
// differ only in case are two different keys.
import { PublicKey } from "@solana/web3.js";

export interface CatalogEntry {
  payTo: string;
  /** The HTTP origin allowed to ask for this payTo, without a path or trailing slash. */
  origin: string;
  name?: string;
  /** The most this service may charge, in base units. */
  maxPrice: bigint | string | number;
}

export interface Service {
  payTo: string;
  origin: string;
  name: string;
  maxPrice: bigint;
}

export interface Catalog {
  lookup(payTo: unknown): Service | null;
  list(): Service[];
}

/** A canonical base58 public key, or null. `new PublicKey` alone also accepts arrays, numbers and buffers. */
export function canonicalAddress(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return null;
  try {
    const key = new PublicKey(value);
    return key.toBase58() === value ? value : null;
  } catch {
    return null;
  }
}

/** A complete HTTP origin, with no path, credentials or alternate spelling. */
export function canonicalOrigin(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") && url.origin === value && !url.username && !url.password ? value : null;
  } catch {
    return null;
  }
}

export function createCatalog(entries: CatalogEntry[] = []): Catalog {
  const byAddress = new Map<string, Service>();
  for (const e of entries) {
    const payTo = canonicalAddress(e?.payTo);
    if (!payTo) throw new Error(`catalog entry has no valid payTo: ${JSON.stringify(e?.payTo)}`);
    const origin = canonicalOrigin(e?.origin);
    if (!origin) throw new Error(`catalog entry ${payTo} needs a canonical HTTP origin`);
    const maxPrice = BigInt(e.maxPrice);
    if (maxPrice <= 0n) throw new Error(`catalog entry ${payTo} needs a positive maxPrice`);
    if (byAddress.has(payTo)) throw new Error(`catalog entry ${payTo} is duplicated`);
    byAddress.set(payTo, { payTo, origin, name: e.name ?? "unnamed service", maxPrice });
  }
  return {
    lookup(payTo) {
      return typeof payTo === "string" ? (byAddress.get(payTo) ?? null) : null;
    },
    list() {
      return [...byAddress.values()];
    },
  };
}

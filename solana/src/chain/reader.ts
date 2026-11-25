// The one place the lanes touch the RPC. Everything above this works on plain
// bytes, so tests can hand the lanes crafted accounts without a validator.
//
// Rule shared by every caller: a throw from here means "could not read", which
// is never the same as "no such account". A missing account comes back as null.
import { Commitment, Connection, PublicKey } from "@solana/web3.js";

export interface RawAccount {
  owner: PublicKey;
  lamports: number;
  executable: boolean;
  data: Buffer;
}

export interface Slice {
  offset: number;
  length: number;
}

export interface AccountReader {
  /** One entry per address, in order. null = the account does not exist. Throws on any RPC failure. */
  getAccounts(addresses: PublicKey[], slice?: Slice): Promise<(RawAccount | null)[]>;
  getSlot(): Promise<number>;
}

// getMultipleAccounts takes at most 100 keys per call.
const MAX_KEYS = 100;

export function connectionReader(
  connection: Connection,
  commitment: Commitment = "confirmed"
): AccountReader {
  return {
    async getAccounts(addresses, slice) {
      const out: (RawAccount | null)[] = [];
      for (let i = 0; i < addresses.length; i += MAX_KEYS) {
        const chunk = addresses.slice(i, i + MAX_KEYS);
        const infos = await connection.getMultipleAccountsInfo(chunk, {
          commitment,
          ...(slice ? { dataSlice: slice } : {}),
        });
        if (!Array.isArray(infos) || infos.length !== chunk.length) {
          throw new Error("RPC returned a malformed getMultipleAccounts response");
        }
        for (const info of infos) {
          out.push(
            info
              ? {
                  owner: info.owner,
                  lamports: info.lamports,
                  executable: info.executable,
                  data: Buffer.from(info.data),
                }
              : null
          );
        }
      }
      return out;
    },
    async getSlot() {
      return connection.getSlot(commitment);
    },
  };
}

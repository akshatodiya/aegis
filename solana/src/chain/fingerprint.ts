// A program's code fingerprint: sha256 of its ELF with the trailing zero
// padding trimmed. ProgramData is allocated larger than the ELF it holds, and
// the padding says nothing about the code.
//
// Two hashes, because a redeploy changes the bytes in two different ways:
//  - `raw` matches a byte-identical ELF deployed under another id;
//  - `normalized` also zeroes every copy of the program's own id, which an
//    Anchor program embeds (declare_id!), so a rebuild of the same source under
//    a new id still matches.
// A clustering signal for blockprog writes, not proof of anything.
import { createHash } from "crypto";
import { PublicKey } from "@solana/web3.js";

import { AccountReader } from "./reader";
import { BPF_LOADER_1, BPF_LOADER_2, BPF_LOADER_UPGRADEABLE, LOADER_V4 } from "../config";
import { LOADER_V4_HEADER_LEN, PROGRAM_DATA_HEADER_LEN, decodeLoaderV3 } from "./decode";

export interface Fingerprint {
  raw: string;
  normalized: string;
  elfBytes: number;
}

export function fingerprintElf(elf: Buffer, programId: PublicKey): Fingerprint {
  let end = elf.length;
  while (end > 0 && elf[end - 1] === 0) end--;
  const trimmed = Buffer.from(elf.subarray(0, end));
  const raw = createHash("sha256").update(trimmed).digest("hex");
  const id = programId.toBuffer();
  const normalizedBytes = Buffer.from(trimmed);
  for (let i = normalizedBytes.indexOf(id); i !== -1; i = normalizedBytes.indexOf(id, i + id.length)) {
    normalizedBytes.fill(0, i, i + id.length);
  }
  const normalized = createHash("sha256").update(normalizedBytes).digest("hex");
  return { raw, normalized, elfBytes: trimmed.length };
}

/** Downloads the program's ELF (can be hundreds of KB) and fingerprints it. null if it isn't a live program. */
export async function programFingerprint(reader: AccountReader, programId: PublicKey): Promise<Fingerprint | null> {
  const [program] = await reader.getAccounts([programId]);
  if (!program) return null;
  if (program.owner.equals(BPF_LOADER_UPGRADEABLE)) {
    const state = decodeLoaderV3(program.data);
    if (state.kind !== "program") return null;
    const [pd] = await reader.getAccounts([state.programData]);
    if (!pd || !pd.owner.equals(BPF_LOADER_UPGRADEABLE)) return null;
    return fingerprintElf(pd.data.subarray(PROGRAM_DATA_HEADER_LEN), programId);
  }
  if (program.owner.equals(LOADER_V4)) return fingerprintElf(program.data.subarray(LOADER_V4_HEADER_LEN), programId);
  if (program.owner.equals(BPF_LOADER_2) || program.owner.equals(BPF_LOADER_1)) return fingerprintElf(program.data, programId);
  return null;
}

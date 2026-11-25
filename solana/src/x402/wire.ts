// Solana's transaction wire format, decoded strictly. The x402 signer decides
// what to sign from these bytes alone, so the parser has to be exact about
// them: it reads the message the signature will cover, and nothing else.
//
//  - every length is a canonical compact-u16 (the shortest encoding, as the
//    runtime requires), and every index is in range;
//  - nothing may follow the message: trailing bytes are an error, not ignored;
//  - legacy and v0 messages are both decoded, and the caller decides which it
//    accepts. Address lookup tables are returned, never resolved.
//
// Layout (solana-sdk `VersionedMessage`): [0x80 | version]? header(3)
// compact(n) keys(32n) blockhash(32) compact(m) instructions
// [compact(k) lookups] for v0. A wire transaction is compact(s) signatures(64s)
// followed by the message.
import { PublicKey } from "@solana/web3.js";

/** The packet limit. A larger transaction can't be sent, so it isn't parsed. */
export const MAX_TRANSACTION_BYTES = 1232;
const VERSION_PREFIX = 0x80;

export interface CompiledInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

export interface LookupTable {
  account: PublicKey;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

export interface DecodedMessage {
  version: "legacy" | 0;
  header: { numRequiredSignatures: number; numReadonlySignedAccounts: number; numReadonlyUnsignedAccounts: number };
  staticKeys: PublicKey[];
  recentBlockhash: string;
  instructions: CompiledInstruction[];
  lookups: LookupTable[];
}

export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WireError";
  }
}

class Reader {
  private at = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get offset(): number {
    return this.at;
  }

  get remaining(): number {
    return this.bytes.length - this.at;
  }

  u8(): number {
    if (this.at >= this.bytes.length) throw new WireError("ran out of bytes");
    return this.bytes[this.at++];
  }

  take(n: number): Uint8Array {
    if (n < 0 || this.at + n > this.bytes.length) throw new WireError(`needs ${n} more bytes, has ${this.remaining}`);
    const out = this.bytes.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  /** compact-u16, shortest form only (1 to 3 bytes, value < 2^16). */
  compactU16(): number {
    let value = 0;
    for (let i = 0; i < 3; i++) {
      const byte = this.u8();
      const bits = byte & 0x7f;
      if (i === 2 && byte > 0x03) throw new WireError("compact-u16 overflows 16 bits");
      value |= bits << (7 * i);
      if ((byte & 0x80) === 0) {
        if (i > 0 && byte === 0) throw new WireError("compact-u16 is not in its shortest form");
        return value;
      }
    }
    throw new WireError("compact-u16 is longer than 3 bytes");
  }
}

export function encodeCompactU16(value: number): number[] {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new WireError(`compact-u16 out of range: ${value}`);
  const out: number[] = [];
  let rest = value;
  for (;;) {
    const bits = rest & 0x7f;
    rest >>= 7;
    if (rest === 0) {
      out.push(bits);
      return out;
    }
    out.push(bits | 0x80);
  }
}

export function decodeMessage(bytes: Uint8Array): DecodedMessage {
  if (bytes.length === 0) throw new WireError("empty message");
  if (bytes.length > MAX_TRANSACTION_BYTES) throw new WireError(`message is ${bytes.length} bytes, over the ${MAX_TRANSACTION_BYTES}-byte packet limit`);
  const r = new Reader(bytes);
  let version: "legacy" | 0 = "legacy";
  if (bytes[0] & VERSION_PREFIX) {
    const v = r.u8() & 0x7f;
    if (v !== 0) throw new WireError(`unsupported message version ${v}`);
    version = 0;
  }
  const header = {
    numRequiredSignatures: r.u8(),
    numReadonlySignedAccounts: r.u8(),
    numReadonlyUnsignedAccounts: r.u8(),
  };
  const keyCount = r.compactU16();
  const staticKeys: PublicKey[] = [];
  for (let i = 0; i < keyCount; i++) staticKeys.push(new PublicKey(r.take(32)));
  if (header.numRequiredSignatures === 0) throw new WireError("a message needs at least one signer (the fee payer)");
  if (header.numRequiredSignatures > keyCount) throw new WireError("more signers than account keys");
  if (header.numReadonlySignedAccounts >= header.numRequiredSignatures) throw new WireError("the fee payer would be read-only");
  if (header.numReadonlyUnsignedAccounts > keyCount - header.numRequiredSignatures) throw new WireError("more read-only unsigned accounts than unsigned accounts");
  // The runtime refuses a message that lists an account twice.
  if (new Set(staticKeys.map((k) => k.toBase58())).size !== keyCount) throw new WireError("an account key is listed twice");
  const recentBlockhash = new PublicKey(r.take(32)).toBase58();

  const instructions: CompiledInstruction[] = [];
  const ixCount = r.compactU16();
  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = r.u8();
    const n = r.compactU16();
    const accountIndexes: number[] = [];
    for (let j = 0; j < n; j++) accountIndexes.push(r.u8());
    const data = r.take(r.compactU16());
    instructions.push({ programIdIndex, accountIndexes, data: Uint8Array.from(data) });
  }

  const lookups: LookupTable[] = [];
  if (version === 0) {
    const lookupCount = r.compactU16();
    for (let i = 0; i < lookupCount; i++) {
      const account = new PublicKey(r.take(32));
      const writableIndexes = Array.from(r.take(r.compactU16()));
      const readonlyIndexes = Array.from(r.take(r.compactU16()));
      lookups.push({ account, writableIndexes, readonlyIndexes });
    }
  }
  if (r.remaining !== 0) throw new WireError(`${r.remaining} bytes follow the message`);

  // Indexes refer to static keys first, then loaded addresses in table order.
  const loaded = lookups.reduce((n, t) => n + t.writableIndexes.length + t.readonlyIndexes.length, 0);
  const total = keyCount + loaded;
  if (total > 256) throw new WireError("more than 256 accounts");
  for (const ix of instructions) {
    if (ix.programIdIndex >= keyCount) throw new WireError("a program id must be a static account key");
    for (const a of ix.accountIndexes) if (a >= total) throw new WireError(`account index ${a} is out of range`);
  }
  return { version, header, staticKeys, recentBlockhash, instructions, lookups };
}

/** Whether static key `index` is writable, by the header's rules. */
export function isWritable(m: DecodedMessage, index: number): boolean {
  const { numRequiredSignatures, numReadonlySignedAccounts, numReadonlyUnsignedAccounts } = m.header;
  if (index < numRequiredSignatures) return index < numRequiredSignatures - numReadonlySignedAccounts;
  return index < m.staticKeys.length - numReadonlyUnsignedAccounts;
}

export function isSigner(m: DecodedMessage, index: number): boolean {
  return index < m.header.numRequiredSignatures;
}

export interface DecodedTransaction {
  signatures: Uint8Array[];
  messageBytes: Uint8Array;
  message: DecodedMessage;
}

export function decodeTransaction(wire: Uint8Array): DecodedTransaction {
  if (wire.length > MAX_TRANSACTION_BYTES) throw new WireError(`transaction is ${wire.length} bytes, over the ${MAX_TRANSACTION_BYTES}-byte packet limit`);
  const r = new Reader(wire);
  const count = r.compactU16();
  const signatures: Uint8Array[] = [];
  for (let i = 0; i < count; i++) signatures.push(Uint8Array.from(r.take(64)));
  const messageBytes = Uint8Array.from(wire.subarray(r.offset));
  const message = decodeMessage(messageBytes);
  if (count !== message.header.numRequiredSignatures) {
    throw new WireError(`${count} signature slots for ${message.header.numRequiredSignatures} required signers`);
  }
  return { signatures, messageBytes, message };
}

export function encodeTransaction(signatures: Uint8Array[], messageBytes: Uint8Array): Uint8Array {
  for (const s of signatures) if (s.length !== 64) throw new WireError("a signature is 64 bytes");
  return Uint8Array.from([...encodeCompactU16(signatures.length), ...signatures.flatMap((s) => Array.from(s)), ...messageBytes]);
}

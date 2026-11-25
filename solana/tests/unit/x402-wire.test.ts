// The strict decoder the signer trusts. It must agree with web3.js on every
// well-formed message, and refuse everything the runtime would refuse (or that
// a lenient parser would quietly accept).
import { expect } from "chai";
import { Keypair, MessageV0, PublicKey, SystemProgram, TransactionMessage, VersionedTransaction } from "@solana/web3.js";

import { decodeMessage, decodeTransaction, encodeCompactU16, encodeTransaction, isSigner, isWritable } from "../../src/x402/wire";
import { key } from "./fixtures";
import { paymentInstructions } from "./x402-fixtures";

const blockhash = () => key().toBase58();

function payment() {
  const us = Keypair.generate().publicKey;
  const feePayer = key();
  const msg = MessageV0.compile({ payerKey: feePayer, recentBlockhash: blockhash(), instructions: paymentInstructions({ feePayer, us, payTo: key(), blockhash: "" }) });
  return { us, feePayer, msg, bytes: msg.serialize() };
}

describe("unit: x402 wire format", () => {
  it("decodes a v0 payment exactly as web3.js compiled it", () => {
    const { msg, bytes, us, feePayer } = payment();
    const d = decodeMessage(bytes);
    expect(d.version).to.equal(0);
    expect(d.header).to.deep.equal(msg.header);
    expect(d.staticKeys.map((k) => k.toBase58())).to.deep.equal(msg.staticAccountKeys.map((k) => k.toBase58()));
    expect(d.recentBlockhash).to.equal(msg.recentBlockhash);
    expect(d.instructions.map((i) => [i.programIdIndex, i.accountIndexes, Buffer.from(i.data).toString("hex")])).to.deep.equal(
      msg.compiledInstructions.map((i) => [i.programIdIndex, i.accountKeyIndexes, Buffer.from(i.data).toString("hex")])
    );
    expect(d.lookups).to.deep.equal([]);
    expect(d.staticKeys[0].equals(feePayer) && d.staticKeys[1].equals(us)).to.equal(true);
    expect([isSigner(d, 0), isWritable(d, 0), isSigner(d, 1), isWritable(d, 1)]).to.deep.equal([true, true, true, false]);
  });

  it("decodes legacy messages and wire transactions, and re-encodes them byte for byte", () => {
    const a = Keypair.generate();
    const legacy = new TransactionMessage({ payerKey: a.publicKey, recentBlockhash: blockhash(), instructions: [SystemProgram.transfer({ fromPubkey: a.publicKey, toPubkey: key(), lamports: 5 })] }).compileToLegacyMessage();
    expect(decodeMessage(legacy.serialize()).version).to.equal("legacy");

    const { msg } = payment();
    const tx = new VersionedTransaction(msg);
    const wire = tx.serialize();
    const d = decodeTransaction(wire);
    expect(d.signatures).to.have.length(2);
    expect(Buffer.from(encodeTransaction(d.signatures, d.messageBytes)).equals(Buffer.from(wire))).to.equal(true);
  });

  it("compact-u16 lengths must be in their shortest form, and fit 16 bits", () => {
    for (const [n, bytes] of [
      [0, [0]],
      [127, [0x7f]],
      [128, [0x80, 0x01]],
      [16383, [0xff, 0x7f]],
      [16384, [0x80, 0x80, 0x01]],
      [65535, [0xff, 0xff, 0x03]],
    ] as const) {
      expect(encodeCompactU16(n), String(n)).to.deep.equal(bytes);
    }
    const { bytes } = payment();
    // The key count is at offset 4 (version byte + 3 header bytes): 8 written as [0x88, 0x00].
    const padded = Uint8Array.from([...bytes.subarray(0, 4), 0x88, 0x00, ...bytes.subarray(5)]);
    expect(() => decodeMessage(padded)).to.throw(/shortest form/);
    const overflow = Uint8Array.from([...bytes.subarray(0, 4), 0xff, 0xff, 0x04, ...bytes.subarray(5)]);
    expect(() => decodeMessage(overflow)).to.throw(/16 bits/);
  });

  it("refuses trailing bytes, truncation, and oversized input", () => {
    const { bytes } = payment();
    expect(() => decodeMessage(Uint8Array.from([...bytes, 0]))).to.throw(/follow the message/);
    expect(() => decodeMessage(bytes.subarray(0, bytes.length - 1))).to.throw(/more bytes|ran out of bytes/);
    expect(() => decodeMessage(bytes.subarray(0, 60))).to.throw(/more bytes|ran out of bytes/);
    expect(() => decodeMessage(new Uint8Array(1233))).to.throw(/packet limit/);
    expect(() => decodeMessage(new Uint8Array(0))).to.throw(/empty/);
  });

  it("refuses what the runtime would: bad indexes, duplicate keys, a read-only fee payer, other versions", () => {
    const { bytes } = payment();
    const d = decodeMessage(bytes);
    // point the transfer's first account past the key list
    const out = Uint8Array.from(bytes);
    const transfer = d.instructions[2];
    const at = Buffer.from(out).indexOf(Buffer.from([transfer.programIdIndex, 4, ...transfer.accountIndexes]));
    out[at + 2] = 200;
    expect(() => decodeMessage(out)).to.throw(/out of range/);

    const dup = Uint8Array.from(bytes);
    dup.set(bytes.subarray(5 + 32, 5 + 64), 5); // key 0 := key 1
    expect(() => decodeMessage(dup)).to.throw(/listed twice/);

    const ro = Uint8Array.from(bytes);
    ro[2] = 2; // two read-only signers out of two
    expect(() => decodeMessage(ro)).to.throw(/fee payer would be read-only/);

    const v1 = Uint8Array.from(bytes);
    v1[0] = 0x81;
    expect(() => decodeMessage(v1)).to.throw(/unsupported message version 1/);
  });

  it("returns lookup tables instead of resolving them", () => {
    const { msg } = payment();
    const withLookup = new MessageV0({
      header: msg.header,
      staticAccountKeys: msg.staticAccountKeys,
      recentBlockhash: msg.recentBlockhash,
      compiledInstructions: msg.compiledInstructions,
      addressTableLookups: [{ accountKey: key(), writableIndexes: [0], readonlyIndexes: [1, 2] }],
    });
    expect(decodeMessage(withLookup.serialize()).lookups[0].readonlyIndexes).to.deep.equal([1, 2]);
  });

  it("a wire transaction needs exactly one signature slot per required signer", () => {
    const { msg } = payment();
    const wire = new VersionedTransaction(msg).serialize();
    const d = decodeTransaction(wire);
    expect(() => decodeTransaction(encodeTransaction([d.signatures[0]], d.messageBytes))).to.throw(/1 signature slots for 2/);
    expect(() => encodeTransaction([new Uint8Array(63)], d.messageBytes)).to.throw(/64 bytes/);
    expect(new PublicKey(d.message.staticKeys[0]).equals(msg.staticAccountKeys[0])).to.equal(true);
  });
});

import { expect } from "chai";
import { PublicKey } from "@solana/web3.js";

import {
  DecodeError,
  decodeClassicMint,
  decodeExtension,
  decodeLoaderV3,
  decodeLoaderV4,
  decodeToken2022Mint,
  decodeTokenAccount,
  parseTlv,
} from "../../src/chain/decode";
import { key, metadataValue, mintBytes, tlv, token2022MintBytes, tokenAccountBytes } from "./fixtures";

describe("unit: decoders", () => {
  describe("token account", () => {
    it("reads every field of the 165-byte base", () => {
      const owner = key();
      const delegate = key();
      const close = key();
      const t = decodeTokenAccount(tokenAccountBytes({ owner, amount: 5n, delegate, delegatedAmount: 3n, state: 2, closeAuthority: close }));
      expect(t.owner.equals(owner)).to.equal(true);
      expect(t.amount).to.equal(5n);
      expect(t.delegate!.equals(delegate)).to.equal(true);
      expect(t.delegatedAmount).to.equal(3n);
      expect(t.state).to.equal("frozen");
      expect(t.closeAuthority!.equals(close)).to.equal(true);
    });

    it("rejects short data, a bad state byte and a bad COption tag", () => {
      expect(() => decodeTokenAccount(Buffer.alloc(100))).to.throw(DecodeError);
      const badState = tokenAccountBytes({ owner: key() });
      badState[108] = 3;
      expect(() => decodeTokenAccount(badState)).to.throw(DecodeError, /state/);
      const badTag = tokenAccountBytes({ owner: key() });
      badTag.writeUInt32LE(2, 72);
      expect(() => decodeTokenAccount(badTag)).to.throw(DecodeError, /COption/);
    });
  });

  describe("mints", () => {
    it("reads a classic mint and insists on exactly 82 bytes", () => {
      const fa = key();
      const m = decodeClassicMint(mintBytes({ mintAuthority: key(), supply: 9n, freezeAuthority: fa }));
      expect(m.supply).to.equal(9n);
      expect(m.decimals).to.equal(6);
      expect(m.freezeAuthority!.equals(fa)).to.equal(true);
      expect(m.extensions).to.deep.equal([]);
      expect(() => decodeClassicMint(Buffer.concat([mintBytes(), Buffer.alloc(1)]))).to.throw(DecodeError);
    });

    it("reads Token-2022 extensions in order", () => {
      const mint = key();
      const pd = key();
      const data = token2022MintBytes(mintBytes(), [
        tlv(12, pd.toBuffer()),
        tlv(19, metadataValue({ mint, name: "USD Coin", symbol: "USDC" })),
      ]);
      const m = decodeToken2022Mint(data);
      expect(m.extensions.map((e) => e.name)).to.deep.equal(["PermanentDelegate", "TokenMetadata"]);
      const perm = m.extensions[0] as any;
      expect(perm.delegate.equals(pd)).to.equal(true);
      const meta = m.extensions[1] as any;
      expect([meta.tokenName, meta.symbol]).to.deep.equal(["USD Coin", "USDC"]);
    });

    it("a Token-2022 mint with no extensions is the plain 82 bytes", () => {
      expect(decodeToken2022Mint(mintBytes()).extensions).to.deep.equal([]);
    });

    it("fails closed on a token account, bad padding or a truncated entry", () => {
      const asAccount = token2022MintBytes(mintBytes(), []);
      asAccount[165] = 2;
      expect(() => decodeToken2022Mint(asAccount)).to.throw(DecodeError, /not a mint/);
      const dirty = token2022MintBytes(mintBytes(), []);
      dirty[100] = 1;
      expect(() => decodeToken2022Mint(dirty)).to.throw(DecodeError, /padding/);
      const truncated = token2022MintBytes(mintBytes(), [tlv(12, key().toBuffer())]).subarray(0, 166 + 4 + 10);
      expect(() => decodeToken2022Mint(Buffer.from(truncated))).to.throw(DecodeError, /past the end/);
    });

    it("keeps an unknown extension type visible instead of dropping it", () => {
      const m = decodeToken2022Mint(token2022MintBytes(mintBytes(), [tlv(99, Buffer.alloc(3))]));
      expect(m.extensions).to.deep.equal([{ type: 99, name: "Unknown" }]);
    });

    it("zero padding after the entries ends the list; data after padding does not", () => {
      expect(parseTlv(Buffer.concat([tlv(9, Buffer.alloc(0)), Buffer.alloc(8)]))).to.have.length(1);
      expect(() => parseTlv(Buffer.concat([Buffer.alloc(4), tlv(9, Buffer.alloc(0))]))).to.throw(DecodeError);
    });

    it("rejects an extension whose length doesn't match its layout", () => {
      expect(() => decodeExtension({ type: 12, value: Buffer.alloc(31) })).to.throw(DecodeError);
      expect(() => decodeExtension({ type: 26, value: Buffer.concat([Buffer.alloc(32), Buffer.from([2])]) })).to.throw(DecodeError);
    });

    it("an all-zero key in an optional field means none", () => {
      const e = decodeExtension({ type: 14, value: Buffer.concat([key().toBuffer(), Buffer.alloc(32)]) }) as any;
      expect(e.programId).to.equal(null);
      expect(e.authority).to.not.equal(null);
    });

    it("reads transfer-fee basis points from both schedules", () => {
      const v = Buffer.alloc(108);
      v.writeUInt16LE(25, 88);
      v.writeUInt16LE(50, 106);
      const e = decodeExtension({ type: 1, value: v }) as any;
      expect([e.olderBps, e.newerBps]).to.deep.equal([25, 50]);
    });
  });

  describe("loaders", () => {
    it("reads loader-v3 program, programdata and buffer headers", () => {
      const pd = key();
      const prog = Buffer.alloc(36);
      prog.writeUInt32LE(2, 0);
      pd.toBuffer().copy(prog, 4);
      const p = decodeLoaderV3(prog);
      expect(p.kind === "program" && p.programData.equals(pd)).to.equal(true);

      const auth = key();
      const data = Buffer.alloc(45);
      data.writeUInt32LE(3, 0);
      data.writeBigUInt64LE(77n, 4);
      data[12] = 1;
      auth.toBuffer().copy(data, 13);
      const d = decodeLoaderV3(data);
      expect(d.kind === "programData" && d.slot === 77n && d.authority!.equals(auth)).to.equal(true);

      const frozen = Buffer.alloc(13);
      frozen.writeUInt32LE(3, 0);
      const f = decodeLoaderV3(frozen);
      expect(f.kind === "programData" && f.authority === null).to.equal(true);

      const buf = Buffer.alloc(37);
      buf.writeUInt32LE(1, 0);
      expect(decodeLoaderV3(buf).kind).to.equal("buffer");
      const bad = Buffer.alloc(8);
      bad.writeUInt32LE(9, 0);
      expect(() => decodeLoaderV3(bad)).to.throw(DecodeError);
    });

    it("reads a loader-v4 header and rejects an unknown status", () => {
      const b = Buffer.alloc(48);
      b.writeBigUInt64LE(5n, 0);
      b.writeBigUInt64LE(1n, 40);
      expect(decodeLoaderV4(b).status).to.equal("deployed");
      b.writeBigUInt64LE(7n, 40);
      expect(() => decodeLoaderV4(b)).to.throw(DecodeError);
    });
  });

  it("uses the canonical key encoding", () => {
    expect(new PublicKey(Buffer.alloc(32)).toBase58()).to.equal("11111111111111111111111111111111");
  });
});

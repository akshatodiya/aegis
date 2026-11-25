// The x402 merchant against a scripted chain: what it accepts, and how it
// answers when it doesn't, in the reference server's terms. Real settlement on
// a validator is in tests/x402.ts.
import { expect } from "chai";
import { AddressInfo } from "net";
import { Connection, Keypair, PublicKey, SendTransactionError, TransactionInstruction, VersionedMessage, VersionedTransaction } from "@solana/web3.js";

import { MEMO_PROGRAM, USDC_MINT, X402_NETWORK } from "../../src/config";
import { associatedTokenAddress } from "../../src/guard/layout";
import { INVALID, Requirement, acceptedMatches, createMerchant, verifyPayment } from "../../src/x402/merchant";
import { key } from "./fixtures";
import { PaymentParts, compile, paymentInstructions } from "./x402-fixtures";

const MEMO = "inv-0001";

/** The Connection calls the merchant makes, scripted. */
class FakeConnection {
  valid = new Set<string>();
  simErr: unknown = null;
  failing = false;
  sent: Uint8Array[] = [];
  sendFails: "rejected" | null = null;
  /** What getSignatureStatuses reports once sent. */
  landing: "confirmed" | "never" = "confirmed";
  priorStatus = false;
  statusReads = 0;
  statusFails = false;

  async isBlockhashValid(bh: string) {
    if (this.failing) throw new Error("429 Too Many Requests");
    return { value: this.valid.has(bh) };
  }
  async simulateTransaction() {
    if (this.failing) throw new Error("429 Too Many Requests");
    return { value: { err: this.simErr } };
  }
  async sendRawTransaction(wire: Uint8Array) {
    if (this.sendFails === "rejected") {
      throw new SendTransactionError({ action: "send", signature: "", transactionMessage: "Blockhash not found", logs: [] });
    }
    this.sent.push(wire);
    return "sig";
  }
  async getSignatureStatuses() {
    this.statusReads++;
    if (this.statusFails) throw new Error("status RPC unavailable");
    if (this.priorStatus) return { value: [{ confirmationStatus: "confirmed", err: null }] };
    if (this.landing === "never" || this.sent.length === 0) return { value: [null] };
    return { value: [{ confirmationStatus: "confirmed", err: null }] };
  }
}

function setup() {
  const conn = new FakeConnection();
  const feePayer = Keypair.generate();
  const us = Keypair.generate();
  const payTo = key();
  const blockhash = key().toBase58();
  conn.valid.add(blockhash);
  const want: Requirement = {
    scheme: "exact",
    network: X402_NETWORK,
    amount: "50000",
    asset: USDC_MINT.toBase58(),
    payTo: payTo.toBase58(),
    maxTimeoutSeconds: 60,
    extra: { feePayer: feePayer.publicKey.toBase58(), memo: MEMO },
  };
  const parts = (o: Partial<PaymentParts> = {}): PaymentParts => ({ feePayer: feePayer.publicKey, us: us.publicKey, payTo, amount: 50_000n, memo: MEMO, blockhash, ...o });
  /** A payment signed by `us`, fee payer slot left empty. */
  const wire = (ixs: TransactionInstruction[] = paymentInstructions(parts()), o: { payerKey?: PublicKey; bh?: string } = {}) => {
    const tx = new VersionedTransaction(VersionedMessage.deserialize(compile(o.payerKey ?? feePayer.publicKey, o.bh ?? blockhash, ixs)));
    tx.sign([us]);
    return tx.serialize();
  };
  const verify = (w: Uint8Array) => verifyPayment(conn as unknown as Connection, w, want, feePayer.publicKey);
  return { conn, feePayer, us, payTo, blockhash, want, parts, wire, verify };
}

async function rejected(p: Promise<unknown>, code: string) {
  const v: any = await p;
  expect(v.ok, v.error).to.equal(false);
  expect(v.code, v.error).to.equal(code);
  expect(v.status).to.equal(402);
}

describe("unit: x402 merchant", () => {
  describe("acceptedMatches", () => {
    it("the requirement echoed verbatim matches, whatever the key order", () => {
      const { want } = setup();
      expect(acceptedMatches(JSON.parse(JSON.stringify(want)), want)).to.equal(true);
      const reordered = Object.fromEntries(Object.entries(want).reverse());
      expect(acceptedMatches(reordered, want)).to.equal(true);
    });

    it("extra may gain keys, and the dynamic ones may differ, but ours must stay", () => {
      const { want } = setup();
      expect(acceptedMatches({ ...want, extra: { ...want.extra, note: "x", recentBlockhash: "other" } }, want)).to.equal(true);
      expect(acceptedMatches({ ...want, extra: { feePayer: want.extra.feePayer } }, want), "memo dropped").to.equal(false);
      expect(acceptedMatches({ ...want, extra: { ...want.extra, feePayer: key().toBase58() } }, want)).to.equal(false);
    });

    it("types matter, and every core field must be there", () => {
      const { want } = setup();
      expect(acceptedMatches({ ...want, amount: 50000 }, want)).to.equal(false);
      expect(acceptedMatches({ ...want, maxTimeoutSeconds: "60" }, want)).to.equal(false);
      const { network, ...noNetwork } = want;
      expect(acceptedMatches(noNetwork, want)).to.equal(false);
      for (const junk of [null, "x", [], 5]) expect(acceptedMatches(junk, want)).to.equal(false);
      void network;
    });
  });

  describe("verifyPayment codes", () => {
    it("a well-formed payment verifies, with the client as payer", async () => {
      const s = setup();
      const v: any = await s.verify(s.wire());
      expect(v.ok, v.error).to.equal(true);
      expect(v.payer.toBase58()).to.equal(s.us.publicKey.toBase58());
    });

    it("refuses 1,400,000 compute units, and accepts the 40,000-unit boundary", async () => {
      const s = setup();
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ units: 1_400_000 })))), INVALID.CU_LIMIT);
      const v = await s.verify(s.wire(paymentInstructions(s.parts({ units: 40_000 }))));
      expect(v.ok).to.equal(true);
    });

    it("each failed check carries the reference facilitator's code", async () => {
      const s = setup();
      await rejected(s.verify(new Uint8Array([1, 2, 3])), INVALID.DECODE);
      await rejected(s.verify(s.wire(undefined, { payerKey: key() })), INVALID.FEE_PAYER);
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ amount: 49_999n })))), INVALID.AMOUNT);
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ destination: associatedTokenAddress(key(), USDC_MINT) })))), INVALID.RECIPIENT);
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ mint: key() })))), INVALID.MINT);
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ microLamports: 5_000_001 })))), INVALID.CU_PRICE_HIGH);
      await rejected(s.verify(s.wire(paymentInstructions(s.parts({ memo: "inv-0002" })))), INVALID.MEMO);
      const twoMemos = [...paymentInstructions(s.parts()), new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [], data: Buffer.from(MEMO) })];
      await rejected(s.verify(s.wire(twoMemos)), INVALID.MEMO_COUNT);
      const stranger = [...paymentInstructions(s.parts()), new TransactionInstruction({ programId: key(), keys: [], data: Buffer.alloc(0) })];
      await rejected(s.verify(s.wire(stranger)), "invalid_exact_svm_payload_unknown_fifth_instruction");
    });

    it("a signature that isn't the payer's, a dead blockhash and a failing simulation", async () => {
      const s = setup();
      const w = s.wire();
      w[1 + 64 + 5] ^= 1; // flip a byte of the payer's signature (slot 1)
      await rejected(s.verify(w), INVALID.SIGNATURE);
      await rejected(s.verify(s.wire(undefined, { bh: key().toBase58() })), INVALID.SIMULATION);
      s.conn.simErr = { InstructionError: [2, { Custom: 1 }] };
      await rejected(s.verify(s.wire()), INVALID.SIMULATION);
    });

    it("a chain it can't read is 503, not the payment's fault", async () => {
      const s = setup();
      s.conn.failing = true;
      const v: any = await s.verify(s.wire());
      expect([v.ok, v.status]).to.deep.equal([false, 503]);
    });
  });

  describe("payment reuse without a socket", () => {
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64");
    const receipt = (h: string) => JSON.parse(Buffer.from(h, "base64").toString("utf8"));
    const payment = (s: ReturnType<typeof setup>) => b64({ x402Version: 2, accepted: s.want, payload: { transaction: Buffer.from(s.wire()).toString("base64") } });
    const serve = (s: ReturnType<typeof setup>, product: () => unknown) =>
      createMerchant({
        connection: s.conn as unknown as Connection,
        feePayer: s.feePayer,
        network: X402_NETWORK,
        services: [{ route: "/weather", name: "Weather", payTo: s.payTo, demand: 50_000n, memo: MEMO, product }],
      });
    function dispatch(server: ReturnType<typeof createMerchant>, header: string): Promise<{ status: number; headers: Record<string, string> }> {
      return new Promise((resolve) => {
        const response = {
          status: 0,
          headers: {} as Record<string, string>,
          writeHead(status: number, headers: Record<string, string>) {
            this.status = status;
            this.headers = headers;
          },
          end() {
            resolve({ status: this.status, headers: this.headers });
          },
        };
        server.emit("request", { url: "/weather", headers: { "payment-signature": header, host: "localhost" } }, response);
      });
    }

    it("reserves a payment before an asynchronous product runs", async () => {
      const s = setup();
      let made = 0;
      let started!: () => void;
      let release!: () => void;
      const entered = new Promise<void>((r) => (started = r));
      const gate = new Promise<void>((r) => (release = r));
      const server = serve(s, async () => {
        made++;
        started();
        await gate;
        return { weather: "sun" };
      });
      const header = payment(s);
      const first = dispatch(server, header);
      await entered;
      const second = dispatch(server, header);
      let timeout!: ReturnType<typeof setTimeout>;
      try {
        const again = await Promise.race([
          second,
          new Promise<never>((_, reject) => (timeout = setTimeout(() => reject(new Error("the duplicate waited for the product")), 500))),
        ]);
        expect([again.status, receipt(again.headers["PAYMENT-RESPONSE"]).errorReason]).to.deep.equal([402, INVALID.DUPLICATE]);
      } finally {
        clearTimeout(timeout);
        release();
      }
      expect((await first).status).to.equal(200);
      expect([made, s.conn.sent.length]).to.deep.equal([1, 1]);
    });

    it("a landed payment after restart is duplicate_settlement, before making the product", async () => {
      const s = setup();
      s.conn.simErr = { InstructionError: [2, "AlreadyProcessed"] };
      s.conn.priorStatus = true;
      let made = 0;
      const server = serve(s, () => ({ n: ++made }));
      const out = await dispatch(server, payment(s));
      expect([out.status, receipt(out.headers["PAYMENT-RESPONSE"]).errorReason]).to.deep.equal([402, INVALID.DUPLICATE]);
      expect([made, s.conn.sent.length, s.conn.statusReads]).to.deep.equal([0, 0, 1]);
    });

    it("a failed product frees the payment for another try", async () => {
      const s = setup();
      let tries = 0;
      const server = serve(s, () => {
        if (++tries === 1) throw new Error("upstream down");
        return { weather: "sun" };
      });
      const header = payment(s);
      expect((await dispatch(server, header)).status).to.equal(502);
      expect((await dispatch(server, header)).status).to.equal(200);
      expect([tries, s.conn.sent.length]).to.deep.equal([2, 1]);
    });

    it("a failed replay-status read keeps the simulation refusal", async () => {
      const s = setup();
      s.conn.simErr = { InstructionError: [2, "AlreadyProcessed"] };
      s.conn.statusFails = true;
      let made = 0;
      const server = serve(s, () => ({ n: ++made }));
      const out = await dispatch(server, payment(s));
      expect([out.status, receipt(out.headers["PAYMENT-REQUIRED"]).error]).to.deep.equal([402, INVALID.SIMULATION]);
      expect([made, s.conn.sent.length, s.conn.statusReads]).to.deep.equal([0, 0, 1]);
    });
  });

  describe("over HTTP", () => {
    let produced = 0;
    async function serve(s: ReturnType<typeof setup>, o: { product?: () => unknown; settleTimeoutMs?: number } = {}) {
      const server = createMerchant({
        connection: s.conn as unknown as Connection,
        feePayer: s.feePayer,
        network: X402_NETWORK,
        settleTimeoutMs: o.settleTimeoutMs ?? 2_000,
        services: [{ route: "/weather", name: "Weather", payTo: s.payTo, demand: 50_000n, memo: MEMO, product: o.product ?? (() => ({ n: ++produced })) }],
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/weather`;
      return { server, url, close: () => new Promise((r) => server.close(r)) };
    }
    const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64");
    const unb64 = (h: string | null) => (h ? JSON.parse(Buffer.from(h, "base64").toString("utf8")) : null);
    const paid = (url: string, header: string, name = "PAYMENT-SIGNATURE") => fetch(url, { headers: { [name]: header } });
    const payment = (s: ReturnType<typeof setup>, w = s.wire(), accepted: unknown = s.want) =>
      b64({ x402Version: 2, accepted, payload: { transaction: Buffer.from(w).toString("base64") } });

    it("unpaid, unreadable, or v1's X-PAYMENT: a plain 402 with the requirements, not cached", async () => {
      const s = setup();
      const m = await serve(s);
      try {
        for (const res of [await fetch(m.url), await paid(m.url, "%%%not base64"), await paid(m.url, payment(s), "X-PAYMENT")]) {
          expect(res.status).to.equal(402);
          expect(res.headers.get("cache-control")).to.equal("no-store");
          const doc = unb64(res.headers.get("payment-required"));
          expect(doc.error).to.equal(undefined);
          expect(acceptedMatches(doc.accepts[0], s.want)).to.equal(true);
        }
        expect(s.conn.sent).to.have.length(0);
      } finally {
        await m.close();
      }
    });

    it("an accepted that isn't ours, or a failed check: 402 with the error in PAYMENT-REQUIRED", async () => {
      const s = setup();
      const m = await serve(s);
      try {
        let res = await paid(m.url, payment(s, s.wire(), { ...s.want, amount: "1" }));
        expect([res.status, unb64(res.headers.get("payment-required")).error]).to.deep.equal([402, INVALID.NO_MATCH]);
        res = await paid(m.url, payment(s, s.wire(paymentInstructions(s.parts({ amount: 1n })))));
        expect([res.status, unb64(res.headers.get("payment-required")).error]).to.deep.equal([402, INVALID.AMOUNT]);
        expect(res.headers.get("payment-response")).to.equal(null);
        expect(s.conn.sent).to.have.length(0);
      } finally {
        await m.close();
      }
    });

    it("settles once: 200 with a receipt naming the client; the same payment again is duplicate_settlement", async () => {
      const s = setup();
      const m = await serve(s);
      try {
        const header = payment(s);
        let res = await paid(m.url, header);
        expect(res.status).to.equal(200);
        const receipt = unb64(res.headers.get("payment-response"));
        expect([receipt.success, receipt.network, receipt.payer]).to.deep.equal([true, X402_NETWORK, s.us.publicKey.toBase58()]);
        const sent = VersionedTransaction.deserialize(s.conn.sent[0]);
        expect(sent.signatures[0].every((b) => b === 0), "the merchant co-signed").to.equal(false);

        res = await paid(m.url, header);
        const again = unb64(res.headers.get("payment-response"));
        expect([res.status, again.success, again.errorReason, again.transaction]).to.deep.equal([402, false, INVALID.DUPLICATE, ""]);
        expect(s.conn.sent).to.have.length(1);
      } finally {
        await m.close();
      }
    });

    it("a send the RPC rejects is transaction_failed with no transaction, and frees the payment for a retry", async () => {
      const s = setup();
      const m = await serve(s);
      try {
        const header = payment(s);
        s.conn.sendFails = "rejected";
        let res = await paid(m.url, header);
        const r = unb64(res.headers.get("payment-response"));
        expect([res.status, r.success, r.errorReason, r.transaction]).to.deep.equal([402, false, INVALID.TX_FAILED, ""]);
        s.conn.sendFails = null;
        res = await paid(m.url, header);
        expect(res.status).to.equal(200);
      } finally {
        await m.close();
      }
    });

    it("a settlement it can't confirm is settlement_pending, names the transaction, and can't be retried", async () => {
      const s = setup();
      s.conn.landing = "never"; // sent, never seen, blockhash still valid
      const m = await serve(s, { settleTimeoutMs: 300 });
      try {
        const header = payment(s);
        let res = await paid(m.url, header);
        const r = unb64(res.headers.get("payment-response"));
        expect([res.status, r.success, r.errorReason]).to.deep.equal([402, false, INVALID.PENDING]);
        expect(r.transaction).to.be.a("string").and.not.equal("");
        res = await paid(m.url, header);
        expect(unb64(res.headers.get("payment-response")).errorReason).to.equal(INVALID.DUPLICATE);
        expect(s.conn.sent).to.have.length(1);
      } finally {
        await m.close();
      }
    });

    it("a service that fails to produce settles nothing", async () => {
      const s = setup();
      const m = await serve(s, {
        product: () => {
          throw new Error("upstream down");
        },
      });
      try {
        const res = await paid(m.url, payment(s));
        expect(res.status).to.equal(502);
        expect(s.conn.sent).to.have.length(0);
      } finally {
        await m.close();
      }
    });
  });
});

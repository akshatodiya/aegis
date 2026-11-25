// GuardClient.send() against a scripted connection: the outcome has to say
// what happened on-chain, because a caller decides whether to retry a payment
// from it. "landed: false" is a promise that it never reached the chain.
import { expect } from "chai";
import { Connection, Keypair, SendTransactionError, SystemProgram } from "@solana/web3.js";

import { TOKEN_PROGRAM, USDC_MINT } from "../../src/config";
import { GuardClient } from "../../src/guard/client";
import { associatedTokenAddress } from "../../src/guard/layout";
import { FakeChain, key, tokenAccountBytes } from "./fixtures";

const GUARD = "CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6";

type Status = { err: unknown; confirmationStatus: "processed" | "confirmed" | "finalized" } | null;

function scripted(o: {
  send?: () => Promise<string>;
  statuses?: Status[]; // one per poll; the last one repeats
  statusThrows?: boolean;
  heights?: number[]; // one per poll; the last one repeats
  tx?: () => Promise<any>;
}) {
  let polls = 0;
  let heightCalls = 0;
  const conn = {
    async getLatestBlockhash() {
      return { blockhash: key().toBase58(), lastValidBlockHeight: 100 };
    },
    async sendRawTransaction() {
      return o.send ? o.send() : "ignored";
    },
    async getSignatureStatuses() {
      if (o.statusThrows) throw new Error("fetch failed");
      const list = o.statuses ?? [null];
      return { context: { slot: 1 }, value: [list[Math.min(polls++, list.length - 1)]] };
    },
    async getBlockHeight() {
      const list = o.heights ?? [50];
      return list[Math.min(heightCalls++, list.length - 1)];
    },
    async getTransaction() {
      return o.tx ? o.tx() : { meta: { err: null, logMessages: ["Program log: ok"] } };
    },
  };
  const client = new GuardClient(conn as unknown as Connection);
  client.pollMs = 1;
  client.sendTimeoutMs = 200;
  return client;
}

const payer = Keypair.generate();
const ix = SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: key(), lamports: 1 });
const send = (client: GuardClient) => client.send([ix], [payer], true);
const confirmed = (err: unknown = null): Status => ({ err, confirmationStatus: "confirmed" });

describe("unit: GuardClient.send", () => {
  it("a confirmed success is ok, and the signature is known even before the send returns", async () => {
    const out = await send(scripted({ statuses: [null, confirmed()] }));
    expect([out.ok, out.landed]).to.deep.equal([true, true]);
    expect(out.signature).to.be.a("string").with.length.greaterThan(80);
    expect(out.logs).to.deep.equal(["Program log: ok"]);
  });

  it("a confirmed failure is landed, not ok, and its code comes from the logs", async () => {
    const logs = [
      `Program ${GUARD} invoke [1]`,
      "Program log: AnchorError occurred. Error Code: Denylisted. Error Number: 6004. Error Message: x.",
      `Program ${GUARD} failed: custom program error: 0x1774`,
    ];
    const out = await send(scripted({ statuses: [confirmed({ InstructionError: [0, { Custom: 6004 }] })], tx: async () => ({ meta: { err: {}, logMessages: logs } }) }));
    expect([out.ok, out.landed, out.code]).to.deep.equal([false, true, "DENYLISTED"]);
  });

  it("the signature status decides success, not the transaction fetch", async () => {
    // fetch fails: still landed and ok
    const lost = await send(scripted({ statuses: [confirmed()], tx: () => Promise.reject(new Error("429")) }));
    expect([lost.ok, lost.landed]).to.deep.equal([true, true]);
    // status says failed, fetch has no meta: still a failure, never a false success
    const noMeta = await send(scripted({ statuses: [confirmed({ InstructionError: [0, "x"] })], tx: async () => ({ meta: null }) }));
    expect([noMeta.ok, noMeta.landed]).to.deep.equal([false, true]);
    expect(noMeta.error).to.match(/logs could not be fetched/);
  });

  it("a transport error after submission is followed up, not reported as 'not sent'", async () => {
    const out = await send(scripted({ send: () => Promise.reject(new Error("socket hang up")), statuses: [null, confirmed()] }));
    expect([out.ok, out.landed]).to.deep.equal([true, true]);
  });

  it("an RPC refusal (preflight) never landed", async () => {
    const refusal = new SendTransactionError({ action: "simulate", signature: "", transactionMessage: "Simulation failed", logs: ["Program log: x"] });
    const out = await send(scripted({ send: () => Promise.reject(refusal) }));
    expect([out.ok, out.landed]).to.deep.equal([false, false]);
  });

  it("an expired blockhash with no trace of the transaction is 'never landed'", async () => {
    const out = await send(scripted({ statuses: [null], heights: [50, 101] }));
    expect([out.ok, out.landed]).to.deep.equal([false, false]);
    expect(out.error).to.match(/blockhash expired/);
  });

  it("one that lands just before the blockhash expires is still found", async () => {
    const out = await send(scripted({ statuses: [null, confirmed()], heights: [101] }));
    expect([out.ok, out.landed]).to.deep.equal([true, true]);
  });

  it("when the chain can't be asked, the answer is 'could not tell', never 'not sent'", async () => {
    const out = await send(scripted({ statusThrows: true }));
    expect([out.ok, out.landed]).to.deep.equal([false, null]);
    expect(out.error).to.match(/could not tell whether .* landed \(fetch failed\); check it before retrying/);
    // processed but never confirmed: the same
    const pending = await send(scripted({ statuses: [{ err: null, confirmationStatus: "processed" }] }));
    expect(pending.landed).to.equal(null);
  });
});

describe("unit: GuardClient.ensureRecipientAta", () => {
  const payer = Keypair.generate();
  const recipient = key();
  const address = associatedTokenAddress(recipient, USDC_MINT);

  function clientFor(data: Buffer) {
    const chain = new FakeChain().set(address, TOKEN_PROGRAM, data);
    const client = new GuardClient({} as Connection);
    (client as any).reader = chain;
    (client as any).config = async () => ({ mint: USDC_MINT });
    return client;
  }

  it("skips a usable account without sending", async () => {
    const out = await clientFor(tokenAccountBytes({ owner: recipient })).ensureRecipientAta(payer, recipient);
    expect([out.address.toBase58(), out.created, out.outcome]).to.deep.equal([address.toBase58(), false, null]);
  });

  it("refuses an account reassigned away from the recipient", async () => {
    try {
      await clientFor(tokenAccountBytes({ owner: key() })).ensureRecipientAta(payer, recipient);
      throw new Error("expected the reassigned account to be refused");
    } catch (err) {
      expect((err as Error).message).to.match(/was reassigned; the recipient cannot spend it/);
    }
  });

  it("refuses a frozen or wrong-mint account", async () => {
    for (const [data, reason] of [
      [tokenAccountBytes({ owner: recipient, state: 2 }), /is frozen/],
      [tokenAccountBytes({ owner: recipient, mint: key() }), /holds another mint/],
    ] as const) {
      try {
        await clientFor(data).ensureRecipientAta(payer, recipient);
        throw new Error("expected the invalid account to be refused");
      } catch (err) {
        expect((err as Error).message).to.match(reason);
      }
    }
  });
});

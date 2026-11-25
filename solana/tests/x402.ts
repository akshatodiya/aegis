// Step 4 on a live local validator: the x402 rail end to end. A real merchant
// on a real socket settles real USDC; the agent's x402 wallet is funded only
// through guarded_pay; every refusal leaves a receipt in the guard's audit log.
// Runs after aegis_guard.ts and lanes.ts (mocha --sort), which initialize the
// guard and share the owner and agent keys.
import { createAssociatedTokenAccount, createMint, getAccount, mintTo } from "@solana/spl-token";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";
import { Server } from "http";
import { AddressInfo } from "net";

import { aegisCheck } from "../src/aegis";
import { createAuditLogger, readRefusals } from "../src/audit";
import { caip2 } from "../src/config";
import { ensureFloat } from "../src/float";
import { GuardClient } from "../src/guard/client";
import { associatedTokenAddress } from "../src/guard/layout";
import { formatUnits } from "../src/units";
import { createCatalog } from "../src/x402/catalog";
import { createAegisX402Fetch, paymentResponse } from "../src/x402/fetch";
import { INVALID, createMerchant } from "../src/x402/merchant";
import { AegisPaymentRefused } from "../src/x402/refused";
import { connectionRpc } from "../src/x402/rpc";
import { createAegisSigner } from "../src/x402/signer";
import { Guard, USDC, loadKeypair, setup, sharedKeys } from "./helpers";

const PRICE = 50_000n; // 0.05 USDC

describe("x402 on a live validator", () => {
  let g: Guard;
  let client: GuardClient;
  let owner: Keypair;
  let agent: Keypair;
  let payer: Keypair;
  let reporter: Keypair;
  let merchant: Server;
  let base: string;
  let network: string;
  const wallet = Keypair.generate(); // the x402 wallet: holds the float, never any SOL
  const weather = Keypair.generate().publicKey;
  const bait = Keypair.generate().publicKey;
  const stranger = Keypair.generate().publicKey;
  const denied = Keypair.generate().publicKey;
  const mintAuthority = loadKeypair("tests/fixtures/mint-authority.json");
  let lookalike: PublicKey;
  let audit: ReturnType<typeof createAuditLogger>;
  let aegisFetch: ReturnType<typeof createAegisX402Fetch>;
  const sentHeaders: string[] = [];
  let signed = 0;
  let produced = 0;
  let feePayer: Keypair;
  let services: Parameters<typeof createMerchant>[0]["services"];

  const usdcOf = async (owner: PublicKey) => (await getAccount(g.connection, associatedTokenAddress(owner, USDC))).amount;

  async function refused(p: Promise<unknown>, code: string): Promise<AegisPaymentRefused> {
    try {
      await p;
    } catch (err) {
      expect(err).to.be.instanceOf(AegisPaymentRefused);
      expect((err as AegisPaymentRefused).code, (err as Error).message).to.equal(code);
      return err as AegisPaymentRefused;
    }
    throw new Error(`expected a ${code} refusal, but it paid`);
  }

  before(async () => {
    g = setup();
    ({ owner, agent } = await sharedKeys(g));
    [payer, reporter] = await Promise.all([g.fundedKeypair(10), g.fundedKeypair(1)]);
    feePayer = await g.fundedKeypair(2);
    client = new GuardClient(g.connection, g.programId, agent.publicKey);
    const cfg = await client.config();
    expect(cfg, "run with aegis_guard.ts first (mocha --sort)").to.not.equal(null);
    await mintTo(g.connection, payer, USDC, cfg!.vault, mintAuthority, 100_000_000n);
    for (const w of [weather, bait, stranger, denied]) await createAssociatedTokenAccount(g.connection, payer, USDC, w);
    lookalike = await createMint(g.connection, payer, payer.publicKey, payer.publicKey, 6);
    await createAssociatedTokenAccount(g.connection, payer, lookalike, weather);
    await g.addEntry(owner, "deny", denied);
    await g.addEntry(owner, "reporter", reporter.publicKey);

    network = caip2(await g.connection.getGenesisHash());
    services = [
      { route: "/weather", name: "Weather", payTo: weather, demand: PRICE, memo: "inv-weather", product: () => (produced++, { forecast: "sun" }) },
        { route: "/bait", name: "Bait", payTo: bait, demand: 5_000_000n, product: { x: 1 } },
        { route: "/stranger", name: "Stranger", payTo: stranger, demand: PRICE, product: { x: 1 } },
        { route: "/lookalike", name: "Look-alike", payTo: weather, demand: PRICE, asset: lookalike, product: { x: 1 } },
      { route: "/denied", name: "Denied", payTo: denied, demand: PRICE, product: { x: 1 } },
    ];
    merchant = createMerchant({ connection: g.connection, feePayer, network, services });
    await new Promise<void>((r) => merchant.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(merchant.address() as AddressInfo).port}`;

    const rpc = connectionRpc(g.connection);
    audit = createAuditLogger({ client, reporter });
    // The default policy check, with the lanes set for a fresh validator as in lanes.ts.
    const signer = createAegisSigner(wallet, {
      rpc,
      network,
      usdc: USDC,
      check: (payTo, amount, destination) =>
        aegisCheck(payTo, formatUnits(amount), { reader: rpc.reader, guard: g.programId, destination, usdcMint: USDC, reasoner: null, recentDeploySlots: 0 }),
      onRefuse: audit.onRefuse,
      onSign: () => signed++,
    });
    const catalog = createCatalog([
      { payTo: weather.toBase58(), origin: base, name: "Weather", maxPrice: 100_000n },
      { payTo: bait.toBase58(), origin: base, name: "Bait", maxPrice: PRICE },
      { payTo: denied.toBase58(), origin: base, name: "Denied", maxPrice: 100_000n },
    ]);
    aegisFetch = createAegisX402Fetch({
      signer,
      catalog,
      rpc,
      network,
      usdc: USDC,
      onRefuse: audit.onRefuse,
      fetchImpl: async (url, init) => {
        const h = new Headers(init?.headers ?? {}).get("payment-signature");
        if (h) sentHeaders.push(h);
        return fetch(url, init);
      },
    });
  });

  after(async () => {
    if (merchant) await new Promise((r) => merchant.close(r));
  });

  it("the float is funded only through guarded_pay, and a full float isn't refilled", async () => {
    const first = await ensureFloat(client, agent, wallet.publicKey, { target: 1_000_000n, min: 500_000n });
    expect(first.toppedUp, first.messages.join("\n")).to.equal(true);
    expect(first.pay!.signature).to.be.a("string");
    expect(await usdcOf(wallet.publicKey)).to.equal(1_000_000n);
    const again = await ensureFloat(client, agent, wallet.publicKey, { target: 1_000_000n, min: 500_000n });
    expect(again.toppedUp).to.equal(false);
    expect(await g.connection.getBalance(wallet.publicKey)).to.equal(0);
  });

  it("a known service at its posted price: the merchant settles real USDC and the receipt names us", async () => {
    const [ours, theirs] = [await usdcOf(wallet.publicKey), await usdcOf(weather)];
    const res = await aegisFetch(`${base}/weather`);
    const body: any = await res.json();
    expect(res.status, JSON.stringify(body)).to.equal(200);
    expect(body.data).to.deep.equal({ forecast: "sun" });
    const receipt = paymentResponse(res)!;
    expect([receipt.success, receipt.network, receipt.payer]).to.deep.equal([true, network, wallet.publicKey.toBase58()]);
    expect([await usdcOf(wallet.publicKey), await usdcOf(weather)]).to.deep.equal([ours - PRICE, theirs + PRICE]);
    expect(await g.connection.getBalance(wallet.publicKey), "the merchant paid the fee").to.equal(0);

    const tx = await g.connection.getTransaction(receipt.transaction as string, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    expect(tx!.meta!.err).to.equal(null);
    const keys = tx!.transaction.message.staticAccountKeys;
    expect(keys[1].toBase58(), "we signed second").to.equal(wallet.publicKey.toBase58());
    expect(signed).to.equal(1);
  });

  it("replay: the same signed payment again is duplicate_settlement and moves nothing", async () => {
    expect(sentHeaders).to.have.length(1);
    const before = await usdcOf(wallet.publicKey);
    const res = await fetch(`${base}/weather`, { headers: { "PAYMENT-SIGNATURE": sentHeaders[0] } });
    const r = paymentResponse(res)!;
    expect([res.status, r.success, r.errorReason]).to.deep.equal([402, false, INVALID.DUPLICATE]);
    expect(await usdcOf(wallet.publicKey)).to.equal(before);
  });

  it("replay after a merchant restart is duplicate_settlement and no product is made", async () => {
    const fresh = createMerchant({ connection: g.connection, feePayer, network, services, log: () => {} });
    await new Promise<void>((r) => fresh.listen(0, "127.0.0.1", r));
    try {
      const [before, made] = [await usdcOf(wallet.publicKey), produced];
      const res = await fetch(`http://127.0.0.1:${(fresh.address() as AddressInfo).port}/weather`, { headers: { "PAYMENT-SIGNATURE": sentHeaders[0] } });
      const r = paymentResponse(res)!;
      expect([res.status, r.success, r.errorReason]).to.deep.equal([402, false, INVALID.DUPLICATE]);
      expect(produced, "no product for a replay").to.equal(made);
      expect(await usdcOf(wallet.publicKey)).to.equal(before);
    } finally {
      await new Promise((r) => fresh.close(r));
    }
  });

  it("bait-and-switch: over the posted price is OVER_POSTED_PRICE, and nothing is signed", async () => {
    const r = await refused(aegisFetch(`${base}/bait`), "OVER_POSTED_PRICE");
    expect([r.recipient, r.amount]).to.deep.equal([bait.toBase58(), 5_000_000n]);
    expect(signed).to.equal(1);
  });

  it("a payee outside the catalog is UNKNOWN_SERVICE", async () => {
    await refused(aegisFetch(`${base}/stranger`), "UNKNOWN_SERVICE");
    expect(signed).to.equal(1);
  });

  it("a look-alike mint is NO_PAYABLE_OPTION, with the lane's findings on that mint", async () => {
    const r = await refused(aegisFetch(`${base}/lookalike`), "NO_PAYABLE_OPTION");
    expect(r.offeredAsset!.mint).to.equal(lookalike.toBase58());
    expect(r.offeredAsset!.facts.map((f) => f.id)).to.include.members(["NOT_PINNED_ASSET", "FREEZE_AUTHORITY"]);
    expect(r.resource?.url).to.equal(`${base}/lookalike`);
  });

  it("a catalogued payee the guard denylists: the catalog alone would pay, the signer refuses DENYLISTED", async () => {
    const before = await usdcOf(wallet.publicKey);
    const r = await refused(aegisFetch(`${base}/denied`), "DENYLISTED");
    expect(r.recipient).to.equal(denied.toBase58());
    expect(signed).to.equal(1);
    expect(sentHeaders, "no payment left the agent").to.have.length(1);
    expect(await usdcOf(wallet.publicKey)).to.equal(before);
  });

  it("every refusal left one on-chain receipt, and the log reads back complete", async () => {
    const out = await audit.flush();
    expect([out.logged, out.failed], out.entries.map((e) => e.error).join("\n")).to.deep.equal([4, 0]);
    const log = await readRefusals(client);
    expect(log.complete, `read ${log.entries.length} of ${log.total}`).to.equal(true);
    const ours = log.entries.filter((e) => e.reporter === reporter.publicKey.toBase58());
    expect(ours.map((e) => e.code).sort()).to.deep.equal(["DENYLISTED", "NO_PAYABLE_OPTION", "OVER_POSTED_PRICE", "UNKNOWN_SERVICE"]);
    const bySig = ours.find((e) => e.code === "DENYLISTED")!;
    expect([bySig.recipient, bySig.amount, bySig.verdict]).to.deep.equal([denied.toBase58(), PRICE, "BLOCK"]);
    expect(ours.find((e) => e.code === "NO_PAYABLE_OPTION")!.recipient).to.equal(null);
  });
});

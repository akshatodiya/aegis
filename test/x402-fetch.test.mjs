// offline tests for the Aegis x402 fetch wrapper (hook A). no network and no
// facilitator: a fake fetch feeds crafted 402 responses, and the real Aegis
// signer signs with an injected verdict so the whole path runs deterministically.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import { createAegisSigner, AegisPaymentRefused } from '../src/x402/signer.js';
import { createAegisX402Fetch } from '../src/x402/fetch.js';
import { createCatalog } from '../src/x402/catalog.js';

const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const USDC = '0x3600000000000000000000000000000000000000';
const CHAIN_ID = 5042002;
const NOW = 1000;
const PAYTO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');

function option(over = {}) {
  return {
    scheme: 'exact',
    network: `eip155:${CHAIN_ID}`,
    asset: USDC,
    payTo: PAYTO,
    amount: '10000', // 0.01 USDC in base units
    maxTimeoutSeconds: 60,
    extra: { assetTransferMethod: 'eip3009', name: 'USDC', version: '2' },
    ...over,
  };
}

// a fake fetch that returns a queued response per call and records the calls.
function fakeFetch(responses) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return responses[calls.length - 1];
  };
  impl.calls = calls;
  return impl;
}

const resp402Body = (opts) =>
  new Response(JSON.stringify({ x402Version: 2, accepts: opts }), {
    status: 402,
    headers: { 'content-type': 'application/json' },
  });
const resp200 = () => new Response('ok', { status: 200 });

function build({ decision = 'PAY', catalogEntries = [{ payTo: PAYTO, name: 'Test API', maxPrice: '10000' }], responses, fetchOpts = {} } = {}) {
  const signer = createAegisSigner(account, {
    usdc: USDC, chainId: CHAIN_ID, now: () => NOW,
    balanceOf: async () => 1000000000n, // offline: a wallet with plenty of float
    check: async () => ({ decision, reasons: ['(injected)'] }),
  });
  const fetchImpl = fakeFetch(responses);
  const aegisFetch = createAegisX402Fetch({
    signer, catalog: createCatalog(catalogEntries), fetchImpl,
    usdc: USDC, chainId: CHAIN_ID, now: () => NOW, ...fetchOpts,
  });
  return { aegisFetch, fetchImpl };
}

test('pays a known service at the posted price and replays with the payment header', async () => {
  const { aegisFetch, fetchImpl } = build({ responses: [resp402Body([option()]), resp200()] });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(fetchImpl.calls.length, 2); // 402 then the paid retry
  assert.ok(fetchImpl.calls[1].init.headers.get('PAYMENT-SIGNATURE'), 'payment header attached');
});

test('refuses a bait-and-switch: amount over the posted price', async () => {
  const { aegisFetch, fetchImpl } = build({ responses: [resp402Body([option({ amount: '5000000' })])] });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && /bait-and-switch/.test(e.reason));
  assert.equal(fetchImpl.calls.length, 1); // never retried, nothing signed
});

test('refuses an unknown payTo not in the catalog', async () => {
  const { aegisFetch, fetchImpl } = build({ catalogEntries: [], responses: [resp402Body([option()])] });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && /not a service/.test(e.reason));
  assert.equal(fetchImpl.calls.length, 1);
});

test('refuses when no option is on our chain / in our USDC', async () => {
  const foreign = option({ network: 'eip155:1', asset: '0x000000000000000000000000000000000000dEaD' });
  const { aegisFetch } = build({ responses: [resp402Body([foreign])] });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && /no acceptable payment/.test(e.reason));
});

test('a BLOCK verdict on payTo stops the payment at the signer', async () => {
  const { aegisFetch, fetchImpl } = build({ decision: 'BLOCK', responses: [resp402Body([option()])] });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused);
  assert.equal(fetchImpl.calls.length, 1);
});

test('parses PaymentRequirements carried in the PAYMENT-REQUIRED header', async () => {
  const headerRes = new Response(null, {
    status: 402,
    headers: { 'PAYMENT-REQUIRED': b64({ x402Version: 2, accepts: [option()] }) },
  });
  const { aegisFetch, fetchImpl } = build({ responses: [headerRes, resp200()] });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(fetchImpl.calls.length, 2);
});

test('passes a non-402 response straight through without paying', async () => {
  const { aegisFetch, fetchImpl } = build({ responses: [resp200()] });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(fetchImpl.calls.length, 1);
});

test('a malformed amount fails closed, never crashes', async () => {
  for (const amount of ['0.01', 'abc', undefined, '0']) {
    const { aegisFetch, fetchImpl } = build({ responses: [resp402Body([option({ amount })])] });
    await assert.rejects(() => aegisFetch('https://api.test/data'),
      (e) => e instanceof AegisPaymentRefused);
    assert.equal(fetchImpl.calls.length, 1); // nothing signed or sent
  }
});

test('a malformed maxTimeoutSeconds is refused, not crashed', async () => {
  const { aegisFetch } = build({ responses: [resp402Body([option({ maxTimeoutSeconds: 'soon' })])] });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused);
});

test('scans past a poison option to a later valid one', async () => {
  const { aegisFetch, fetchImpl } = build({
    responses: [resp402Body([option({ amount: 'abc' }), option()]), resp200()],
  });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(fetchImpl.calls.length, 2);
});

// ---- the per-payment cap: the ASK_HUMAN lane on the x402 rail ----
// the catalog entry posts a high price so these payments are honest, just big.
const bigService = [{ payTo: PAYTO, name: 'Pricey API', maxPrice: '10000' }];

test('over the cap with no human wired in fails closed with ASK_HUMAN', async () => {
  const { aegisFetch, fetchImpl } = build({
    catalogEntries: bigService,
    responses: [resp402Body([option()])],
    fetchOpts: { maxPerPayment: 5000n },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && e.verdict === 'ASK_HUMAN' && /no human/.test(e.reason));
  assert.equal(fetchImpl.calls.length, 1); // nothing signed
});

test('over the cap, human approves -> the payment proceeds', async () => {
  const asked = [];
  const { aegisFetch, fetchImpl } = build({
    catalogEntries: bigService,
    responses: [resp402Body([option()]), resp200()],
    fetchOpts: { maxPerPayment: 5000n, askHuman: async (info) => { asked.push(info); return true; } },
  });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(fetchImpl.calls.length, 2);
  // the human saw real context, not a bare yes/no
  assert.equal(asked.length, 1);
  assert.equal(asked[0].service.name, 'Pricey API');
  assert.equal(asked[0].amount, 10000n);
  assert.equal(asked[0].cap, 5000n);
});

test('over the cap, human declines -> refused with ASK_HUMAN, nothing signed', async () => {
  const { aegisFetch, fetchImpl } = build({
    catalogEntries: bigService,
    responses: [resp402Body([option()])],
    fetchOpts: { maxPerPayment: 5000n, askHuman: async () => false },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && e.verdict === 'ASK_HUMAN' && /declined/.test(e.reason));
  assert.equal(fetchImpl.calls.length, 1);
});

test('a human yes does not bypass the signer - a BLOCK payTo still refuses', async () => {
  // the property Aegis stands on: approval at the fetch layer clears the CAP,
  // nothing else. hook B still runs the full verdict before any signature.
  let asked = 0;
  const { aegisFetch, fetchImpl } = build({
    decision: 'BLOCK',
    catalogEntries: bigService,
    responses: [resp402Body([option()])],
    fetchOpts: { maxPerPayment: 5000n, askHuman: async () => { asked++; return true; } },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && e.verdict === 'BLOCK');
  assert.equal(asked, 1); // the human said yes...
  assert.equal(fetchImpl.calls.length, 1); // ...and the signer still refused to sign.
});

test('an unknown payTo is refused before any human is asked', async () => {
  // ordering matters: we never put "approve paying an unknown recipient?" in
  // front of a person - unknown is a hard refusal, the cap question never comes.
  let asked = 0;
  const { aegisFetch } = build({
    catalogEntries: [],
    responses: [resp402Body([option()])],
    fetchOpts: { maxPerPayment: 5000n, askHuman: async () => { asked++; return true; } },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && /not a service/.test(e.reason));
  assert.equal(asked, 0);
});

test('under the cap the human is never bothered', async () => {
  let asked = 0;
  const { aegisFetch } = build({
    responses: [resp402Body([option()]), resp200()],
    fetchOpts: { maxPerPayment: 20000n, askHuman: async () => { asked++; return true; } },
  });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  assert.equal(asked, 0);
});

test('replies to a v1 (maxAmountRequired) 402 with a single X-PAYMENT header', async () => {
  const v1opt = {
    scheme: 'exact', network: `eip155:${CHAIN_ID}`, asset: USDC, payTo: PAYTO,
    maxAmountRequired: '10000', maxTimeoutSeconds: 60, extra: { name: 'USDC', version: '2' },
  };
  const body = new Response(JSON.stringify({ x402Version: 1, accepts: [v1opt] }),
    { status: 402, headers: { 'content-type': 'application/json' } });
  const { aegisFetch, fetchImpl } = build({ responses: [body, resp200()] });
  const res = await aegisFetch('https://api.test/data');
  assert.equal(res.status, 200);
  const h = fetchImpl.calls[1].init.headers;
  assert.ok(h.get('X-PAYMENT'), 'v1 header set');
  assert.equal(h.get('PAYMENT-SIGNATURE'), null, 'no v2 header on a v1 reply');
  const inner = JSON.parse(Buffer.from(h.get('X-PAYMENT'), 'base64').toString());
  assert.equal(inner.x402Version, 1);
});

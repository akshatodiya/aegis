// integration tests for the mock x402 merchant: the full client<->merchant round
// trip over REAL localhost http. the Aegis fetch wrapper and signer are the real
// ones (verdict injected so no chain and no llm); only the clock is real, since
// the merchant checks the authorization window against actual time.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import { createAegisSigner, AegisPaymentRefused } from '../src/x402/signer.js';
import { createAegisX402Fetch } from '../src/x402/fetch.js';
import { createCatalog } from '../src/x402/catalog.js';
import { createMockMerchant } from '../src/x402/mock-service.js';

const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const USDC = '0x3600000000000000000000000000000000000000';
const CHAIN_ID = 5042002;
const DOMAIN = { name: 'USDC', version: '2' };
const PAYTO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const PRICE = 100_000n; // 0.10 USDC

let server, base;

before(async () => {
  server = createMockMerchant({
    usdc: USDC,
    chainId: CHAIN_ID,
    domain: DOMAIN,
    services: [
      { route: '/data', name: 'Test API', payTo: PAYTO, demand: PRICE, product: { answer: 42 } },
      { route: '/bait', name: 'Test API', payTo: PAYTO, demand: PRICE * 50n, product: { answer: 42 } },
      // a service that computes its product from the request, the way the paid
      // Aegis screening does, rather than returning a fixture
      { route: '/computed', name: 'Test API', payTo: PAYTO, demand: PRICE,
        product: (url) => ({ echo: url.searchParams.get('q'), answer: 42 }) },
      // and one that fails to produce it, to pin the nonce behaviour
      { route: '/broken', name: 'Test API', payTo: PAYTO, demand: PRICE,
        product: () => { throw new Error('the oracle is down'); } },
    ],
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

// a real client wired to the real merchant; records payment headers on the way
// out so tests can replay/tamper them like a hostile network position would.
// with `intercept`, the signed retry is captured but never delivered - so the
// authorization exists, signed and fresh, without the merchant burning its nonce.
function client({ recorded = [], intercept = false } = {}) {
  const signer = createAegisSigner(account, {
    usdc: USDC, chainId: CHAIN_ID,
    balanceOf: async () => 1000000000n, // offline: a wallet with plenty of float
    check: async () => ({ decision: 'PAY', reasons: ['(injected)'] }),
  });
  const fetchImpl = async (url, init) => {
    const header = init?.headers?.get?.('PAYMENT-SIGNATURE');
    if (header) {
      recorded.push(header);
      if (intercept) return new Response('{}', { status: 200 });
    }
    return fetch(url, init);
  };
  return createAegisX402Fetch({
    signer, fetchImpl,
    catalog: createCatalog([{ payTo: PAYTO, name: 'Test API', maxPrice: PRICE.toString() }]),
    usdc: USDC, chainId: CHAIN_ID, domain: DOMAIN,
  });
}

test('the 402 says what is for sale, where the spec puts it', async () => {
  // x402 v2 hangs the ResourceInfo off the PaymentRequired document rather than
  // off each requirement (spec 5.1.2) - one resource, possibly several ways to
  // pay for it. the client reads it from there; this pins the merchant sending
  // it from there, so the two halves of the demo can't drift apart.
  const res = await fetch(`${base}/data`);
  assert.equal(res.status, 402);
  const doc = await res.json();
  assert.equal(doc.resource.url, `${base}/data`);
  assert.equal(doc.resource.mimeType, 'application/json');
  assert.equal(typeof doc.resource.description, 'string');
  assert.equal(doc.accepts[0].resource, undefined);
  // and the header-carried copy says the same thing, since a client may read
  // either one and must not get a different answer depending which it chose.
  const header = JSON.parse(Buffer.from(res.headers.get('PAYMENT-REQUIRED'), 'base64').toString());
  assert.deepEqual(header.resource, doc.resource);
});

test('full round trip: 402 challenge -> signed authorization -> verified -> 200', async () => {
  const aegisFetch = client();
  const res = await aegisFetch(`${base}/data`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.data, { answer: 42 });
  // the merchant is honest about what it did and did not do
  assert.equal(body.payment.settled, false);
  assert.equal(body.payment.from, account.address);
});

test('an unpaid request gets a parseable 402 challenge', async () => {
  const res = await fetch(`${base}/data`);
  assert.equal(res.status, 402);
  const doc = JSON.parse(Buffer.from(res.headers.get('payment-required'), 'base64').toString());
  assert.equal(doc.x402Version, 2);
  assert.equal(doc.accepts[0].payTo, PAYTO);
  assert.equal(doc.accepts[0].amount, PRICE.toString());
});

test('a replayed authorization is rejected - one signature settles once', async () => {
  const recorded = [];
  const aegisFetch = client({ recorded });
  const first = await aegisFetch(`${base}/data`);
  assert.equal(first.status, 200);
  assert.equal(recorded.length, 1);

  // same header again, straight at the merchant: the nonce is already burned
  const replay = await fetch(`${base}/data`, { headers: { 'PAYMENT-SIGNATURE': recorded[0] } });
  assert.equal(replay.status, 409);
});

test('a tampered authorization dies on the signature check', async () => {
  // capture a signed authorization WITHOUT delivering it, so its nonce is still
  // fresh - otherwise the replay check (which runs before crypto, same order as
  // the token contract) would mask the signature failure with a 409.
  const recorded = [];
  const aegisFetch = client({ recorded, intercept: true });
  assert.equal((await aegisFetch(`${base}/data`)).status, 200);

  // tamper with a field the merchant does not pre-check against its own demand:
  // widen validAfter. window still passes, but the signature no longer matches -
  // which is exactly why a facilitator can't alter what the agent signed.
  const payload = JSON.parse(Buffer.from(recorded[0], 'base64').toString());
  payload.payload.authorization.validAfter = String(Number(payload.payload.authorization.validAfter) - 1000);
  const tampered = Buffer.from(JSON.stringify(payload)).toString('base64');
  const res = await fetch(`${base}/data`, { headers: { 'PAYMENT-SIGNATURE': tampered } });
  assert.equal(res.status, 401);
});

test('an authorization for the wrong amount is rejected before crypto', async () => {
  const recorded = [];
  const aegisFetch = client({ recorded });
  assert.equal((await aegisFetch(`${base}/data`)).status, 200);

  const payload = JSON.parse(Buffer.from(recorded[0], 'base64').toString());
  payload.payload.authorization.value = '1'; // pay 0.000001 for a 0.10 product
  const tampered = Buffer.from(JSON.stringify(payload)).toString('base64');
  const res = await fetch(`${base}/data`, { headers: { 'PAYMENT-SIGNATURE': tampered } });
  assert.equal(res.status, 400);
});

test('a garbage payment header is a 400, not a crash', async () => {
  const res = await fetch(`${base}/data`, { headers: { 'PAYMENT-SIGNATURE': '!!!not-a-payment!!!' } });
  assert.equal(res.status, 400);
});

test('a signature that is valid JSON but broken crypto is a 401, not a crash', async () => {
  // parses fine, decodes fine, then dies inside the crypto - the merchant must
  // treat a viem throw exactly like a wrong signature, not fall over.
  const recorded = [];
  const aegisFetch = client({ recorded, intercept: true });
  assert.equal((await aegisFetch(`${base}/data`)).status, 200);

  const payload = JSON.parse(Buffer.from(recorded[0], 'base64').toString());
  payload.payload.signature = '0x1234'; // not a 65-byte signature
  const res = await fetch(`${base}/data`, {
    headers: { 'PAYMENT-SIGNATURE': Buffer.from(JSON.stringify(payload)).toString('base64') },
  });
  assert.equal(res.status, 401);
});

test('the client refuses the bait route before any signature exists', async () => {
  const aegisFetch = client();
  await assert.rejects(() => aegisFetch(`${base}/bait`),
    (e) => e instanceof AegisPaymentRefused && /bait-and-switch/.test(e.reason));
});

test('a service can compute its product from the request', async () => {
  // this is what lets Aegis sell a screening: the payload is derived from the
  // paid request, not a fixture chosen at startup.
  const res = await client()(`${base}/computed?q=hello`);
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).data, { echo: 'hello', answer: 42 });
});

test('a service that fails to produce its result does not burn the nonce', async () => {
  // the buyer paid and got nothing, but that failure is the seller's fault, so
  // the authorization must survive for a retry rather than being spent on a 502.
  const recorded = [];
  const aegisFetch = client({ recorded, intercept: true });
  assert.equal((await aegisFetch(`${base}/broken`)).status, 200); // captured, not delivered

  const send = () => fetch(`${base}/broken`, { headers: { 'PAYMENT-SIGNATURE': recorded[0] } });
  const first = await send();
  assert.equal(first.status, 502, 'the seller failed to produce the goods');

  // the same authorization again must NOT come back as a replay
  const second = await send();
  assert.equal(second.status, 502);
  assert.notEqual(second.status, 409, 'the nonce was burned on a failure that was ours');
});

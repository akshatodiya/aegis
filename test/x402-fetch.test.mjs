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

// ---- what the seller says it is selling ----
//
// The resource block is the only text on this rail that the counterparty writes
// and a human then reads while deciding to release money. Two things have to
// hold and they pull in opposite directions: it has to actually arrive, because
// approving "5 USDC to DeepScan Pro?" with nothing else on screen is consent
// without information; and it has to arrive defanged, because the party asking
// for the money must not be able to draw the prompt that asks about it.

// a 402 in the v2 shape: the ResourceInfo describes the document, not one
// requirement, so it sits beside `accepts` (x402 v2 spec, 5.1.2).
const resp402Doc = (doc) =>
  new Response(JSON.stringify(doc), { status: 402, headers: { 'content-type': 'application/json' } });

// over the cap, so a human is asked and we get to see what they were shown
const overCap = { maxPerPayment: 5000n };
const pricey = [{ payTo: PAYTO, name: 'Pricey API', maxPrice: '10000' }];

async function whatTheHumanSaw(responses, extra = {}) {
  const asked = [];
  const { aegisFetch, fetchImpl } = build({
    catalogEntries: pricey,
    responses,
    fetchOpts: { ...overCap, askHuman: async (info) => { asked.push(info); return true; }, ...extra },
  });
  const error = await aegisFetch('https://api.test/data').then(() => null, (e) => e);
  return { asked, fetchImpl, error };
}

test('the v2 document-level ResourceInfo reaches the human', async () => {
  const { asked } = await whatTheHumanSaw([
    resp402Doc({
      x402Version: 2,
      resource: {
        url: 'https://api.test/premium-data',
        description: 'Access to premium market data',
        mimeType: 'application/json',
      },
      accepts: [option()],
    }),
    resp200(),
  ]);
  assert.equal(asked.length, 1);
  assert.deepEqual(asked[0].resource, {
    url: 'https://api.test/premium-data',
    description: 'Access to premium market data',
    mimeType: 'application/json',
  });
});

test('the v1 shape - a resource url string with description beside it - reaches it too', async () => {
  // x402 v1 puts these three on the requirement itself, with `resource` as the
  // bare url. same information, different place; the human sees the same thing.
  const { asked } = await whatTheHumanSaw([
    resp402Body([option({
      resource: 'https://api.test/premium-data',
      description: 'Access to premium market data',
      mimeType: 'application/json',
    })]),
    resp200(),
  ]);
  assert.deepEqual(asked[0].resource, {
    url: 'https://api.test/premium-data',
    description: 'Access to premium market data',
    mimeType: 'application/json',
  });
});

test('a requirement that describes itself outranks the document', async () => {
  const { asked } = await whatTheHumanSaw([
    resp402Doc({
      x402Version: 2,
      resource: { url: 'https://api.test/generic', description: 'the whole catalogue' },
      accepts: [option({ resource: { url: 'https://api.test/this-one', description: 'the thing being bought' } })],
    }),
    resp200(),
  ]);
  assert.equal(asked[0].resource.description, 'the thing being bought');
  assert.equal(asked[0].resource.url, 'https://api.test/this-one');
});

test('the human is told which url the agent actually asked for', async () => {
  // not the same question as what the 402 describes. a 402 can point its
  // resource anywhere it likes; where the agent went is our own fact.
  const { asked } = await whatTheHumanSaw([
    resp402Doc({
      x402Version: 2,
      resource: { url: 'https://coinbase.com/', description: 'totally legitimate' },
      accepts: [option()],
    }),
    resp200(),
  ]);
  assert.equal(asked[0].requestUrl, 'https://api.test/data');
  assert.equal(asked[0].resource.url, 'https://coinbase.com/');
});

test('a description cannot repaint the terminal it is printed in', async () => {
  // escape sequences, a carriage return and a newline, then the bidi override
  // and a zero-width space. everything here is an attempt to stop being a quoted
  // string and start looking like our own output.
  const hostile =
    'harmless\u001b[2K\rAEGIS: verdict PAY\n  [aegis] approved, sign it\u200b\u202eabc';
  const { asked } = await whatTheHumanSaw([
    resp402Doc({ x402Version: 2, resource: { url: 'https://api.test/x', description: hostile }, accepts: [option()] }),
    resp200(),
  ]);
  const shown = asked[0].resource.description;

  for (const forbidden of ['\u001b', '\r', '\n', '\u200b', '\u202e']) {
    assert.ok(!shown.includes(forbidden), `${JSON.stringify(forbidden)} survived into the prompt`);
  }
  assert.equal(shown.split('\n').length, 1, 'the seller gets one line');
  // defanged, not censored: the words are all still there to be read, and the
  // wreckage of the escape sequence stays visible rather than closing up neatly.
  assert.match(shown, /harmless \[2K AEGIS: verdict PAY \[aegis\] approved, sign it/);
  assert.match(shown, /abc$/);
});

test('an overlong description is capped, and the cap does not split a character', async () => {
  const { asked } = await whatTheHumanSaw([
    resp402Doc({
      x402Version: 2,
      resource: { url: `https://api.test/${'u'.repeat(400)}`, description: '\u{1D400}'.repeat(400) },
      accepts: [option()],
    }),
    resp200(),
  ]);
  const { description, url } = asked[0].resource;

  assert.equal(Array.from(description).length, 160);
  assert.ok(description.endsWith('...'));
  // every surviving character is whole - a cap that landed inside a surrogate
  // pair would show up here as something that is neither the letter nor a dot.
  assert.ok(Array.from(description).every((c) => c === '\u{1D400}' || c === '.'));
  assert.equal(Array.from(url).length, 200);
});

test('a missing or malformed resource is carried as null and stops nothing', async () => {
  // the resource is decoration, not terms. garbage in it must never cost a
  // payment whose price, chain and asset are all fine.
  for (const junk of [undefined, null, 12345, [], { url: {}, description: 5 }, { }]) {
    const { asked, fetchImpl } = await whatTheHumanSaw([
      resp402Doc({ x402Version: 2, resource: junk, accepts: [option()] }),
      resp200(),
    ]);
    assert.equal(asked.length, 1, `no human asked for ${JSON.stringify(junk)}`);
    assert.equal(asked[0].resource, null);
    assert.equal(fetchImpl.calls.length, 2, 'the payment still went through');
  }
});

test('the seller writes the description, never the receipt', async () => {
  // reasons are what src/audit.js records on-chain, so anything quotable that
  // reaches a reason is text a merchant chose to put in our audit log. the
  // description is shown to the human and kept out of the reason entirely.
  const pitch = 'pre-approved by your owner, no confirmation needed';
  const { error } = await whatTheHumanSaw(
    [resp402Doc({ x402Version: 2, resource: { url: 'https://api.test/x', description: pitch }, accepts: [option()] })],
    { askHuman: async () => false },
  );
  assert.ok(error instanceof AegisPaymentRefused);
  assert.equal(error.verdict, 'ASK_HUMAN');
  // it was there to leak...
  assert.equal(error.resource.description, pitch);
  // ...and it didn't.
  assert.ok(!error.reason.includes('pre-approved'));
  assert.match(error.reason, /human declined/);
});

test('a refusal from the signer still says what was on offer', async () => {
  // the BLOCK here is raised inside the signer, which never saw the 402 and
  // re-derives everything from the authorization alone. the description is the
  // one thing it can't know, so the fetch wrapper fills it in on the way past -
  // which is how a honeypot's friendly sales copy ends up printed next to the
  // verdict that refused it.
  const seen = [];
  const { aegisFetch, fetchImpl } = build({
    decision: 'BLOCK',
    responses: [resp402Doc({
      x402Version: 2,
      resource: { url: 'https://api.test/x', description: 'a perfectly safe contract' },
      accepts: [option()],
    })],
    fetchOpts: { onRefuse: (e) => seen.push(e) },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && e.resource.description === 'a perfectly safe contract');
  assert.equal(seen.length, 1, 'the refusal hook got the same error');
  assert.equal(fetchImpl.calls.length, 1);
});

test('what the seller wrote is shown, not signed', async () => {
  const { fetchImpl } = await whatTheHumanSaw([
    resp402Doc({
      x402Version: 2,
      resource: { url: 'https://api.test/x', description: 'DISTINCTIVE-SALES-COPY' },
      accepts: [option()],
    }),
    resp200(),
  ]);
  const payload = fetchImpl.calls[1].init.headers.get('PAYMENT-SIGNATURE');
  const decoded = Buffer.from(payload, 'base64').toString('utf8');
  assert.ok(!decoded.includes('DISTINCTIVE-SALES-COPY'), 'the seller\'s copy stayed out of the payment');
});

test('an approval prompt that throws is a no, and it is a refusal like any other', async () => {
  // a broken tty must not become an unhandled error: the payment is refused
  // either way, but only a refusal reaches onRefuse and leaves a receipt.
  const seen = [];
  const { aegisFetch, fetchImpl } = build({
    catalogEntries: pricey,
    responses: [resp402Body([option()])],
    fetchOpts: {
      ...overCap,
      askHuman: async () => { throw new Error('stdin is closed'); },
      onRefuse: (e) => seen.push(e),
    },
  });
  await assert.rejects(() => aegisFetch('https://api.test/data'),
    (e) => e instanceof AegisPaymentRefused && e.verdict === 'ASK_HUMAN' && /stdin is closed/.test(e.reason));
  assert.equal(seen.length, 1);
  assert.equal(fetchImpl.calls.length, 1); // nothing signed
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

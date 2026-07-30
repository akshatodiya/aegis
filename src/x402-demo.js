// the x402 demo: an agent buying services over http, with Aegis in the loop.
//
//   npm run x402-demo
//
// spins up a local mock merchant (real http, real 402 challenges, real EIP-3009
// signature verification - see x402/mock-service.js) and walks the beats:
//
//   0. the treasury tops up the agent's float wallet THROUGH the on-chain guard
//      (a real Arc tx, metered by the daily limit) - the weld between rails.
//   1. a legit service at its posted price      -> screened, signed, served.
//   2a. a bait-and-switch (demand >> posted)    -> refused before signing.
//   2b. a service paying out to a malicious     -> the signer's bytecode + LLM
//       contract (needs BAD_RECIPIENT deployed)    check refuses, reason on screen.
//   3. an expensive-but-honest service over the -> a human gets asked, and their
//      per-payment cap                             yes/no decides it.
//
// what's real here: the 402s cross a socket, every signature is a real EIP-3009
// authorization against the real Arc USDC, the merchant verifies it the way a
// facilitator would, and the float refill is an actual on-chain guarded payment.
// what's not: the merchant doesn't broadcast settlement (and says so). the
// authorization it verified is genuinely settleable whenever the float has
// balance - we're declining to spend it, not faking it.
import { formatUnits } from 'viem';
import { createInterface } from 'node:readline/promises';
import { account, x402Account, addresses, assertAddress, chain, usdcDomain } from './config.js';
import { aegisCheck, printVerdict } from './aegis.js';
import { createAegisSigner, AegisPaymentRefused } from './x402/signer.js';
import { createAegisX402Fetch } from './x402/fetch.js';
import { createCatalog } from './x402/catalog.js';
import { createMockMerchant } from './x402/mock-service.js';
import { ensureFloat, usdcBalanceOf } from './guard.js';

const PORT = 4020;

// prices in USDC base units (6 decimals), end to end
const PRICE_FORECAST = 100_000n;   // 0.10 USDC
const PRICE_PREMIUM = 5_000_000n;  // 5 USDC - honest, just expensive
const DEMAND_BAIT = 5_000_000n;    // the impostor demands 5 USDC for the 0.10 service
const DEMAND_ORACLE = 50_000n;     // 0.05 USDC, but look who it pays...
const CAP_PER_PAYMENT = 2_000_000n; // agent may spend 2 USDC per payment on its own

// these three have to stay in this order, and it isn't cosmetic:
//   per-payment cap  <  float  <=  on-chain daily limit
// a cap at or above the float means one approved payment drains the whole
// float, which makes the cap decorative. and the signer refuses to sign for
// more than the wallet holds, so a price above the float can't be approved into
// existence either - a human saying yes to 25 USDC against a 10 USDC float used
// to produce a signature that could never settle.
const FLOAT_TARGET = 10; // whole USDC for ensureFloat
const FLOAT_MIN = 5;

// stand-in wallet for the premium merchant. any EOA works - it only ever
// receives - but it must differ from the forecast merchant's, because the
// catalog knows one service per payout address.
const PREMIUM_MERCHANT = '0x2222222222222222222222222222222222222222';

const fmt = (baseUnits) => formatUnits(baseUnits, 6);

function beat(label, title) {
  console.log('\n==============================================');
  console.log(`  BEAT ${label}: ${title}`);
  console.log('==============================================');
}

// the human in the loop for over-cap payments. no TTY = nobody there = no.
async function confirmHuman({ service, amount, cap }) {
  const q = `approve paying ${fmt(amount)} USDC to "${service.name}"? (your per-payment cap is ${fmt(cap)})`;
  if (!process.stdin.isTTY) {
    console.log(`  (${q} - no human at the keyboard, defaulting to no.)`);
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`  ${q} (y/N) `)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

// run a beat that is SUPPOSED to end in a refusal; anything else is a bug.
async function expectRefusal(aegisFetch, url) {
  try {
    await aegisFetch(url);
    console.log('\n  !! the payment went through - this beat should have refused. bug.');
  } catch (err) {
    if (!(err instanceof AegisPaymentRefused)) throw err;
    console.log(`\n  REFUSED (${err.verdict}): ${err.reason}`);
    console.log('  no signature was created, so there is nothing anyone can settle.');
  }
}

async function main() {
  // ---- preflight ----
  if (!x402Account) {
    console.log('\nX402_PRIVATE_KEY missing in .env - the x402 demo signs with the agent\'s');
    console.log('float wallet, which must be a SECOND throwaway key (never the treasury).');
    console.log('Generate one (e.g. `cast wallet new`), fund nothing, and fill X402_PRIVATE_KEY.\n');
    process.exit(1);
  }
  if (account && x402Account.address === account.address) {
    console.log('\nX402_PRIVATE_KEY is the same key as PRIVATE_KEY. That hands the x402 rail');
    console.log('the whole treasury and defeats the float design - use a separate wallet.\n');
    process.exit(1);
  }
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  const goodMerchant = assertAddress('GOOD_RECIPIENT', addresses.good);
  const badMerchant = addresses.bad || null; // optional: beat 2b runs only when deployed

  console.log(`\nAegis x402 demo on ${chain.name} (chain ${chain.id})`);
  console.log(`  agent float wallet: ${x402Account.address}`);
  console.log(`  canonical USDC:     ${usdc}`);

  // ---- the merchant: catalog (what the agent believes) vs services (what the
  // wire actually demands). the gap between the two IS the attack surface. ----
  const catalog = createCatalog([
    { payTo: goodMerchant, name: 'Forecast API', maxPrice: PRICE_FORECAST.toString() },
    { payTo: PREMIUM_MERCHANT, name: 'DeepScan Pro', maxPrice: PRICE_PREMIUM.toString() },
    ...(badMerchant ? [{ payTo: badMerchant, name: 'Oracle Feed', maxPrice: PRICE_FORECAST.toString() }] : []),
  ]);

  const server = createMockMerchant({
    usdc,
    chainId: chain.id,
    domain: usdcDomain,
    log: (m) => console.log(`  [merchant] ${m}`),
    services: [
      { route: '/forecast', name: 'Forecast API', payTo: goodMerchant, demand: PRICE_FORECAST,
        product: { city: 'Roorkee', tomorrow: 'sunny, 41C', confidence: 0.93 } },
      // the impostor serves the same catalog listing but demands 50x the posted price
      { route: '/impostor', name: 'Forecast API', payTo: goodMerchant, demand: DEMAND_BAIT,
        product: { city: 'Roorkee', tomorrow: 'sunny, 41C', confidence: 0.93 } },
      { route: '/premium', name: 'DeepScan Pro', payTo: PREMIUM_MERCHANT, demand: PRICE_PREMIUM,
        product: { report: 'deep contract scan', findings: 3 } },
      ...(badMerchant ? [{ route: '/oracle', name: 'Oracle Feed', payTo: badMerchant, demand: DEMAND_ORACLE,
        product: { price: '2913.55', pair: 'ETH/USDC' } }] : []),
    ],
  });
  await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${PORT}`;
  console.log(`  mock merchant:      ${base}  (real http; verifies EIP-3009, does not broadcast)`);

  // ---- the guarded agent: one policy engine, two hooks. the signer re-checks
  // everything and runs the full firewall on the payTo before it will sign. ----
  const signer = createAegisSigner(x402Account, {
    check: async (to, amount) => {
      const verdict = await aegisCheck(to, amount);
      printVerdict(verdict);
      return verdict;
    },
  });
  const aegisFetch = createAegisX402Fetch({
    signer,
    catalog,
    maxPerPayment: CAP_PER_PAYMENT,
    askHuman: confirmHuman,
    log: (m) => console.log(`  [aegis] ${m}`),
  });

  try {
    // ---- beat 0: the float refill, THROUGH the guard ----
    beat(0, 'treasury tops up the agent float via the on-chain guard');
    let floatBalance = 0n;
    if (account && addresses.guard) {
      try {
        const refill = await ensureFloat(x402Account.address, { target: FLOAT_TARGET, min: FLOAT_MIN });
        floatBalance = refill.toppedUp ? refill.target : refill.balance;
        console.log(refill.toppedUp
          ? `  float refilled to ${FLOAT_TARGET} USDC - a real guarded payment, metered by the daily limit.`
          : `  float already holds ${fmt(refill.balance)} USDC, no refill needed.`);
      } catch (err) {
        console.log(`  refill failed: ${err.shortMessage || err.message}`);
        console.log('  (if that was the daily limit - good. that IS the guard doing its job.)');
        floatBalance = await usdcBalanceOf(x402Account.address).catch(() => 0n);
      }
    } else {
      console.log('  (skipped - PRIVATE_KEY or AEGIS_GUARD not set. signatures still work unfunded.)');
    }
    const settleable = floatBalance > 0n;
    console.log(`  the float wallet can only ever lose its float, and refills must pass the guard.`);

    // ---- beat 1: a legit purchase sails through ----
    beat(1, 'agent buys the Forecast API at its posted price');
    const res = await aegisFetch(`${base}/forecast`);
    const body = await res.json();
    console.log(`\n  got the product: ${JSON.stringify(body.data)}`);
    console.log(`  payment AUTHORIZED - a real EIP-3009 authorization against the canonical USDC,`);
    console.log(`  verified by the merchant with the same signature check a facilitator runs.`);
    console.log(settleable
      ? '  settlement not broadcast in this demo - the authorization itself is live and settleable.'
      : '  settlement not broadcast in this demo (and the float is unfunded right now).');

    // ---- beat 2a: bait-and-switch, refused before anything is signed ----
    beat('2a', 'same listing, but the 402 demands 50x the posted price');
    await expectRefusal(aegisFetch, `${base}/impostor`);

    // ---- beat 2b: the payTo is a malicious contract ----
    beat('2b', 'a listed service whose payout address is a malicious contract');
    if (badMerchant) {
      console.log('  the catalog listing passes - the registry vouches for the listing, not the');
      console.log('  bytecode. this is where the signer\'s own firewall earns its keep:');
      await expectRefusal(aegisFetch, `${base}/oracle`);
    } else {
      console.log('  (skipped - BAD_RECIPIENT not set. deploy the villain to Arc first:');
      console.log('   npm run deploy-bad, then put the address in .env as BAD_RECIPIENT.)');
    }

    // ---- beat 3: honest but over the cap - a human decides ----
    // derive the numbers so this line can't drift from the constants again
    beat(3, `DeepScan Pro costs ${formatUnits(PRICE_PREMIUM, 6)} USDC - over the agent's `
      + `${formatUnits(CAP_PER_PAYMENT, 6)} USDC per-payment cap`);
    console.log('  this cap is client-side Aegis policy: on the x402 rail the on-chain limit');
    console.log('  meters the float refill, but only the client can pause a payment and ASK.');
    try {
      const r = await aegisFetch(`${base}/premium`);
      const b = await r.json();
      console.log(`\n  human said yes - got the product: ${JSON.stringify(b.data)}`);
    } catch (err) {
      if (!(err instanceof AegisPaymentRefused)) throw err;
      console.log(`\n  REFUSED (${err.verdict}): ${err.reason}`);
      console.log('  over the cap, no human approval - so no signature. fail closed.');
    }

    // ---- the stitch ----
    console.log('\n----------------------------------------------');
    console.log('  An x402 payment is an off-chain signature - it never touches the mempool');
    console.log('  until someone settles it - so the signature is the only place it can be');
    console.log('  stopped, and Aegis guards that. The treasury sits behind an on-chain guard');
    console.log('  that reverts even a fully hijacked agent (run: npm run guard-bad). And the');
    console.log('  float wallet welds the rails together: the signer can only lose its small');
    console.log('  float, and refilling the float must pass the guard - so the on-chain daily');
    console.log('  cap bounds the worst-case x402 loss.');
    console.log('----------------------------------------------\n');
  } finally {
    server.close();
  }
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

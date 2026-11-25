// Aegis, sold over the rail it defends.
//
// Every other demo here points Aegis at the agent's own payments. This one turns
// it around: Aegis is the merchant. An agent that wants a recipient screened
// pays a fraction of a cent over x402 and gets a verdict back.
//
// The point isn't the money, it's that the firewall needs no privileged
// position to be useful. It is a service an agent can buy at the moment it
// matters, priced per call, with no account, no API key and no signup - which is
// the whole argument for x402 in the first place. And it costs no new
// infrastructure: this reuses the same mock merchant, the same signer and the
// same fetch wrapper the other demos already use, with the screening as the
// product instead of a weather fixture.
//
// One honest note: the buyer here is the agent's own x402 float wallet, because
// it's the wallet in this repo that holds a float and is meant to sign. In a
// real deployment the buyer is somebody else's agent entirely. The mechanism is
// identical either way - that is the point of paying over an open protocol.
import { formatUnits, isAddress } from 'viem';
import { x402Account, addresses, chain, usdcDomain, assertAddress } from './config.js';
import { aegisCheck } from './aegis.js';
import { createAegisSigner } from './x402/signer.js';
import { createAegisX402Fetch } from './x402/fetch.js';
import { createCatalog } from './x402/catalog.js';
import { createMockMerchant } from './x402/mock-service.js';

const PORT = 4022;
const PRICE = 1_000n; // 0.001 USDC per screening
const CAP_PER_PAYMENT = 100_000n; // 0.10 USDC - a screening is far under it

// where the operator of this Aegis instance gets paid. a plain EOA: it only
// ever receives, and it must not be a contract or the buyer's own firewall
// would (correctly) want it vetted first.
const AEGIS_OPERATOR = '0x4444444444444444444444444444444444444444';

function line(text) {
  console.log(`\n----------------------------------------------\n  ${text}\n----------------------------------------------`);
}

async function main() {
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  if (!x402Account) {
    throw new Error('X402_PRIVATE_KEY missing in .env - this demo needs the float wallet to sign.');
  }

  // the thing being sold: a real screening, run per request, against the real
  // chain. the query string is the input, the verdict is the product.
  async function screen(url) {
    const recipient = url.searchParams.get('recipient');
    const amount = Number(url.searchParams.get('amount') ?? '1');
    if (!recipient || !isAddress(recipient)) {
      throw new Error('screen: pass ?recipient=0x... (a valid address)');
    }
    console.log(`  [aegis-service] paid screening requested for ${recipient} ...`);
    const verdict = await aegisCheck(recipient, amount);
    return {
      recipient: verdict.recipient,
      amount: verdict.amount,
      decision: verdict.decision,
      reasons: verdict.reasons,
      lanes: Object.fromEntries(
        Object.entries(verdict.lanes).map(([k, v]) => [k, { level: v.level, reason: v.reason }]),
      ),
    };
  }

  const server = createMockMerchant({
    usdc,
    chainId: chain.id,
    domain: usdcDomain,
    log: (m) => console.log(`  [aegis-service] ${m}`),
    services: [{
      route: '/screen',
      name: 'Aegis Screening',
      payTo: AEGIS_OPERATOR,
      demand: PRICE,
      product: screen,
    }],
  });
  await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));

  const base = `http://127.0.0.1:${PORT}`;
  console.log(`\n  Aegis screening service: ${base}/screen  at ${formatUnits(PRICE, 6)} USDC per call`);
  console.log(`  buyer (the agent):       ${x402Account.address}`);

  // the buyer is an ordinary Aegis-guarded agent. nothing about it is special
  // cased for this demo - same signer, same wrapper, same policy.
  const signer = createAegisSigner(x402Account);
  const buy = createAegisX402Fetch({
    signer,
    catalog: createCatalog([
      { payTo: AEGIS_OPERATOR, name: 'Aegis Screening', maxPrice: PRICE.toString() },
    ]),
    maxPerPayment: CAP_PER_PAYMENT,
    log: (m) => console.log(`  [buyer] ${m}`),
  });

  // screen the honeypot if we have one, otherwise a plain EOA still shows the
  // paid round trip working end to end.
  const target = addresses.bad && isAddress(addresses.bad)
    ? addresses.bad
    : '0x000000000000000000000000000000000000dEaD';

  line(`the agent pays ${formatUnits(PRICE, 6)} USDC to have ${target} screened`);
  const res = await buy(`${base}/screen?recipient=${target}&amount=1`);
  const body = await res.json();

  if (res.status !== 200) {
    console.log(`\n  the purchase did not complete: ${res.status} ${JSON.stringify(body)}\n`);
    return;
  }

  const v = body.data;
  console.log(`\n  paid ${formatUnits(BigInt(body.payment.amount), 6)} USDC, got a verdict back:\n`);
  console.log(`    recipient  ${v.recipient}`);
  console.log(`    decision   ${v.decision}`);
  for (const r of v.reasons) console.log(`    - ${r}`);

  line('Aegis screened a recipient for a fraction of a cent, over the same x402\n'
    + '  rail it protects. No API key, no account, no signup - the agent paid at\n'
    + '  the moment it needed an answer. The firewall is not just infrastructure\n'
    + '  the agent runs, it is a service the agent can buy.');
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\nerror:', err.shortMessage || err.message);
    process.exit(1);
  });

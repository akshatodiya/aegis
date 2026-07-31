// tests for the half of the behavior lane that actually talks to a chain.
//
// behavior.test.mjs covers the pure decision. This covers timesPaid: the getLogs
// query, the window arithmetic, the base-units-to-USDC conversion, and the
// failure path that has to return null instead of guessing zero. All of it ran
// only in live demos before, which means a drifted event signature or an
// off-by-one in the window would have failed silently in front of a judge.
//
// No anvil: a stub JSON-RPC server answers eth_blockNumber and eth_getLogs, so
// the lane's real network path runs offline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { encodeEventTopics, parseAbiItem, toHex, pad } from 'viem';

const PAID = parseAbiItem('event Paid(address indexed agent, address indexed to, uint256 amount)');
const TOPIC0 = encodeEventTopics({ abi: [PAID], eventName: 'Paid' })[0];

const GUARD = '0x00000000000000000000000000000000000000ff';
const AGENT = '0x00000000000000000000000000000000000000a1';
const LATEST = 1_234_567n;

const RECIPIENT = {
  fresh: '0x0000000000000000000000000000000000000010',
  dust: '0x0000000000000000000000000000000000000020',
  real: '0x0000000000000000000000000000000000000030',
  broken: '0x0000000000000000000000000000000000000040',
};

// what the stub chain will say it paid each recipient, in USDC base units.
const HISTORY = {
  [RECIPIENT.fresh]: [],
  [RECIPIENT.dust]: [1_000_000n], // exactly 1 USDC, the farming payment
  [RECIPIENT.real]: [50_000_000n, 200_000_000n, 10_000_000n], // largest is 200
};

function fakeLog(to, amount, i) {
  return {
    address: GUARD,
    topics: [TOPIC0, pad(AGENT, { size: 32 }), pad(to, { size: 32 })],
    data: toHex(amount, { size: 32 }),
    blockNumber: toHex(LATEST - 100n + BigInt(i)),
    blockHash: pad('0xbeef', { size: 32 }),
    transactionHash: pad(toHex(i + 1), { size: 32 }),
    transactionIndex: '0x0',
    logIndex: toHex(i),
    removed: false,
  };
}

// the last eth_getLogs filter the lane sent, so the window math can be asserted
// rather than assumed.
let lastFilter = null;

const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const { id, method, params } = JSON.parse(raw);
    const reply = (body) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id, ...body }));
    };

    if (method === 'eth_chainId') return reply({ result: '0xaa36a7' });
    if (method === 'eth_blockNumber') return reply({ result: toHex(LATEST) });
    if (method === 'eth_getLogs') {
      lastFilter = params[0];
      // topic[2] is the indexed `to`. pull the recipient back out of it.
      const toTopic = String(params[0].topics?.[2] ?? '').toLowerCase();
      const match = Object.keys(HISTORY).find(
        (addr) => pad(addr, { size: 32 }).toLowerCase() === toTopic,
      );
      if (!match) {
        // stand-in for the real failure: public gateways reject a range they
        // don't like, and the lane must not read that as "no payments".
        return reply({ error: { code: -32005, message: 'query returned more than 10000 results' } });
      }
      return reply({ result: HISTORY[match].map((amt, i) => fakeLog(match, amt, i)) });
    }
    return reply({ result: '0x0' });
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));

// config.js binds env at import time, so this has to happen before the lane is
// loaded, and the import below has to be the only one in this file.
process.env.CHAIN = 'sepolia';
process.env.RPC_URL = `http://127.0.0.1:${server.address().port}`;
process.env.AEGIS_GUARD = GUARD;
const { timesPaid, behaviorVerdict } = await import('../src/lanes/behavior.js');

test('a recipient with no history reads as zero, not as unknown', async () => {
  const paid = await timesPaid(RECIPIENT.fresh);
  assert.deepEqual(paid, { count: 0, largest: 0 });
});

test('the largest prior payment is converted out of base units', async () => {
  const paid = await timesPaid(RECIPIENT.real);
  assert.equal(paid.count, 3);
  // 200_000_000 base units is 200 USDC, not 200000000 - this is the 6-decimal
  // boundary the lane crosses, and getting it wrong scales trust by a million.
  assert.equal(paid.largest, 200);
});

test('a single dust payment is reported at its real size', async () => {
  const paid = await timesPaid(RECIPIENT.dust);
  assert.deepEqual(paid, { count: 1, largest: 1 });
});

test('a failed log query returns null, never an empty history', async () => {
  // the whole three-state design rests on this: "we could not read it" must not
  // arrive at the verdict wearing the same shape as "they have never been paid".
  const paid = await timesPaid(RECIPIENT.broken);
  assert.equal(paid, null);
});

test('the query window is the documented 50k blocks back from head', async () => {
  await timesPaid(RECIPIENT.real);
  assert.equal(BigInt(lastFilter.fromBlock), LATEST - 50_000n);
  assert.equal(lastFilter.toBlock, 'latest');
  assert.equal(String(lastFilter.address).toLowerCase(), GUARD);
});

test('the lane filters on the recipient, not just on the event', async () => {
  await timesPaid(RECIPIENT.dust);
  assert.equal(lastFilter.topics[0], TOPIC0, 'must match the deployed Paid signature');
  assert.equal(
    String(lastFilter.topics[2]).toLowerCase(),
    pad(RECIPIENT.dust, { size: 32 }).toLowerCase(),
    'to is the second indexed arg, so it belongs in topic 2',
  );
});

// deliberately not tested here: the `if (!addresses.guard) return null` branch.
// config.js binds that address at import, so the only way to reach it from this
// file would be to null the env after the fact and assert on a null that the
// error path produces anyway - a test that passes without exercising the line it
// names. It needs its own process to test honestly, and it is one line.

test('end to end: a real chain read feeds the farming case correctly', async () => {
  // the whole point of the lane, wired together: the dust history the attacker
  // manufactured must not clear a large payment.
  const dust = await timesPaid(RECIPIENT.dust);
  assert.equal(behaviorVerdict(500, dust).escalate, true);

  // and a genuine payee with real history is still not bothered.
  const real = await timesPaid(RECIPIENT.real);
  assert.equal(behaviorVerdict(500, real).escalate, false);
});

test.after(() => server.close());

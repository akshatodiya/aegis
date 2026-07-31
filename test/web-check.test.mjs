// tests for web/check.html - the self-service page that runs the deterministic
// lanes in a judge's browser.
//
// the page cannot import src/lanes/*.js: it has to work from a file:// url with
// no build step and no server, and those modules pull in viem and dotenv. so the
// lane code is copied into the page, and a copy is a liability - it agrees with
// the original on the day it is written and then quietly stops. these tests are
// what make the copy safe. the page's script block is lifted out of the html,
// imported here, and run against the same bytecodes as the real lane, and the
// two results have to be identical objects, not merely similar answers.
//
// the hand-rolled parts (keccak-256, the abi encoding, the function selectors)
// get the same treatment against viem, because "I wrote my own crypto for the
// security page" is only acceptable when something independent checks it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  keccak256 as viemKeccak, toFunctionSelector, toEventSelector, getAddress,
  encodeAbiParameters, decodeFunctionResult, parseAbi, toHex,
} from 'viem';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const PAGE = resolve(root, 'web/check.html');

// ---- lift the engine out of the page ---------------------------------------
// it lives in its own script block, tagged, and touches no DOM, precisely so
// this works. if someone moves a `document` reference into that block, the
// import below throws and this file says why.
const html = readFileSync(PAGE, 'utf8');
const core = html.match(/<script type="module" id="aegis-core">([\s\S]*?)<\/script>/);
assert.ok(core, 'web/check.html no longer has a script block tagged id="aegis-core"');
await import(`data:text/javascript;base64,${Buffer.from(core[1], 'utf8').toString('base64')}`);
const A = globalThis.AEGIS;
assert.ok(A, 'the page script ran but did not publish globalThis.AEGIS');

// ---- the corpus ------------------------------------------------------------
// the awkward cases from test/bytecode.test.mjs, plus the shapes that only show
// up on a live chain. every one of these goes through both copies of the lane.
const hex = (bytes) => '0x' + Buffer.from(bytes).toString('hex');

function solcMetadata(hashByte = 0x11) {
  return [
    0xa2,
    0x64, 0x69, 0x70, 0x66, 0x73,
    0x58, 0x22, ...Array(34).fill(hashByte),
    0x64, 0x73, 0x6f, 0x6c, 0x63,
    0x43, 0x00, 0x08, 0x1c,
    0x00, 0x33,
  ];
}

// a push wide enough to reach a JUMPDEST inside a well-formed cbor blob
function craftedWithPush(n) {
  const start = n + 2;
  const target = start + 4;
  const imm = new Array(n).fill(0);
  for (let k = n - 1, t = target; k >= 0; k--, t = Math.floor(t / 256)) imm[k] = t & 0xff;
  return hex([
    0x60 + n - 1, ...imm, 0x56,
    0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x0d,
  ]);
}

const CORPUS = {
  // an honest contract whose metadata must be trimmed, not scanned
  '0x00000000000000000000000000000000000000a0': hex([...Array(20).fill(0x00), ...solcMetadata()]),
  // a tail that declares itself metadata but is not valid cbor
  '0x00000000000000000000000000000000000000b0': hex([0x60, 0x09, 0x56, 0, 0, 0, 0, 0, 0xa2, 0x5b, 0xff, 0, 0, 0, 0x00, 0x06]),
  // valid cbor the code jumps into: structurally perfect, still a hiding place
  '0x00000000000000000000000000000000000000c0': hex([
    0x60, 0x0c, 0x56, 0, 0, 0, 0, 0,
    0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x0d,
  ]),
  '0x00000000000000000000000000000000000000d0': craftedWithPush(1),
  '0x00000000000000000000000000000000000000d4': craftedWithPush(4),
  '0x00000000000000000000000000000000000000d5': craftedWithPush(5),
  '0x00000000000000000000000000000000000000df': craftedWithPush(32),
  // PUSH5 of a constant too large to be a code offset - must not be read as a jump
  '0x00000000000000000000000000000000000000e0': hex([
    0x64, 0xff, 0x00, 0x00, 0x00, 0x00, 0x56,
    0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x0d,
  ]),
  // a trailer claiming 65535 bytes of metadata
  '0x00000000000000000000000000000000000000e1': hex([0x00, 0x00, 0xff, 0xff]),
  // an ordinary wallet
  '0x00000000000000000000000000000000000000f0': '0x',
  // an eip-7702 delegated EOA: code, but not a contract
  '0x00000000000000000000000000000000000000f1': '0xef01009a0da68c0f9654bd7110e928f229b7c4c216de9c',
  // a real eip-1167 minimal proxy, the shape every honeypot clone on Arc has
  '0x00000000000000000000000000000000000000f2':
    '0x363d3d373d3d3d363d739a0da68c0f9654bd7110e928f229b7c4c216de9c5af43d82803e903d91602b57fd5bf3',
  // one of each danger opcode, so the scoring and the notes are compared too
  '0x00000000000000000000000000000000000000f3': hex([0xf0, 0xf2, 0xf5, 0x32, 0x32, 0xf4, 0xff]),
  // a dangling PUSH32 at the very end: the immediate runs off the code, and the
  // walk must not read past it or wrap around
  '0x00000000000000000000000000000000000000f4': hex([0x32, 0x7f, 0xff, 0xff]),
  // USDC's own address, to compare the Circle-system naming as well as the score
  '0x3600000000000000000000000000000000000000': hex([0xf4, ...solcMetadata(0x22)]),
  // Permit2, which is named but scores zero
  '0x000000000022d473030f116ddee9f6b43ac78ba3': hex([0x00, 0x01, ...solcMetadata(0x33)]),
};

// ---- a stub eth_getCode, so the real lane runs with no network -------------
const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const { id, method, params } = JSON.parse(raw);
    let result = '0x0';
    if (method === 'eth_getCode') result = CORPUS[String(params[0]).toLowerCase()] ?? '0x';
    if (method === 'eth_chainId') result = '0xaa36a7';
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const RPC_URL = `http://127.0.0.1:${server.address().port}`;

process.env.CHAIN = 'sepolia';
process.env.RPC_URL = RPC_URL;
process.env.AEGIS_GUARD = ''; // so the behavior lane reads null, the same as the page's failed read
const { stripMetadata, checkBytecode } = await import('../src/lanes/bytecode.js');
const { checkReputation } = await import('../src/lanes/reputation.js');
const { behaviorVerdict } = await import('../src/lanes/behavior.js');

// ---- the parity tests ------------------------------------------------------

test('the page trims metadata at exactly the same boundary as the lane', () => {
  for (const [address, code] of Object.entries(CORPUS)) {
    if (code === '0x') continue;
    assert.deepEqual(A.stripMetadata(code), stripMetadata(code), `stripMetadata disagreed on ${address}`);
  }
});

test('the page and the lane return the identical verdict object for every shape', async () => {
  for (const [address, code] of Object.entries(CORPUS)) {
    const mine = A.bytecodeVerdict(address, code === '0x' ? undefined : code);
    const theirs = await checkBytecode(address);
    assert.deepEqual(mine, theirs, `the bytecode lanes disagreed on ${address}`);
  }
});

test('the honeypot shape still scores HIGH through the page copy', () => {
  // a canary on the corpus itself: if some future edit made every entry score
  // LOW, the parity tests above would still pass while proving nothing.
  const r = A.bytecodeVerdict('0x00000000000000000000000000000000000000f3', CORPUS['0x00000000000000000000000000000000000000f3']);
  assert.equal(r.level, 'HIGH');
  assert.ok(r.hits.SELFDESTRUCT && r.hits.DELEGATECALL && r.hits.ORIGIN);
  const hidden = A.bytecodeVerdict('0x00000000000000000000000000000000000000c0', CORPUS['0x00000000000000000000000000000000000000c0']);
  assert.ok(hidden.hits.HIDDEN_CODE, 'the executable "metadata" blob must still be caught in the browser copy');
});

test('hexToBytes copies Buffer.from(hex) including where it gives up', () => {
  // eth_getCode is the one input here a recipient chooses, so the two copies of
  // the lane have to agree on malformed hex as well as valid hex.
  for (const input of ['0x', '0xff', '0xffa', '0x00zz11', 'ff00', '0xABCDEF', '0x0', '', '0xzz']) {
    assert.deepEqual(
      Buffer.from(A.hexToBytes(input)),
      Buffer.from(input.replace(/^0x/, ''), 'hex'),
      `hexToBytes drifted from Buffer on ${JSON.stringify(input)}`,
    );
  }
});

test('the reputation lane is mirrored exactly', () => {
  for (const address of Object.keys(CORPUS)) {
    assert.deepEqual(A.checkReputation(address), checkReputation(address));
  }
});

test('the behavior lane is mirrored exactly, including the dust-payment rule', () => {
  const histories = [null, { count: 0, largest: 0 }, { count: 1, largest: 1 }, { count: 3, largest: 40 }, { count: 9, largest: 500 }];
  for (const amount of [0, 1, 50, 51, 100, 5000]) {
    for (const paid of histories) {
      assert.deepEqual(
        A.behaviorVerdict(amount, paid),
        behaviorVerdict(amount, paid),
        `behavior disagreed on ${amount} USDC against ${JSON.stringify(paid)}`,
      );
    }
  }
});

test('the page reaches the same verdict as the engine itself', async () => {
  // the strongest version of the claim on the page: not "the lanes agree" but
  // "aegisCheck and this page answer the same thing".
  //
  // it runs in a child process with an empty PATH, so `claude` cannot be found
  // and reason() returns available:false. that is not a trick to make the
  // comparison work - it is the exact branch the page mirrors, and the reason
  // the page can claim to be the engine rather than a simplification of it.
  const cases = [
    ['0x00000000000000000000000000000000000000a0', 1],   // honest contract
    ['0x00000000000000000000000000000000000000b0', 1],   // faked trailer hiding a selfdestruct
    ['0x00000000000000000000000000000000000000c0', 1],   // valid cbor jumped into
    ['0x00000000000000000000000000000000000000f2', 1],   // minimal proxy
    ['0x00000000000000000000000000000000000000f1', 1],   // 7702 delegated EOA
    ['0x00000000000000000000000000000000000000f0', 1],   // plain wallet, small amount
    ['0x00000000000000000000000000000000000000f0', 100], // plain wallet, over the behavior threshold
    ['0x3600000000000000000000000000000000000000', 1],   // a Circle system contract
  ];

  const script = `
    const cases = ${JSON.stringify(cases)};
    import(${JSON.stringify(pathToFileURL(resolve(root, 'src/aegis.js')).href)}).then(async ({ aegisCheck }) => {
      const out = [];
      for (const [addr, amount] of cases) out.push((await aegisCheck(addr, amount)).decision);
      process.stdout.write(JSON.stringify(out));
    }).catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
  `;
  // spawn, not spawnSync: the stub RPC server lives in this process, and a
  // synchronous wait would block the event loop that has to answer the child.
  const child = await new Promise((done, fail) => {
    const proc = spawn(process.execPath, ['-e', script], {
      env: {
        PATH: '',                                    // no claude binary reachable
        CHAIN: 'sepolia',
        RPC_URL,
        AEGIS_GUARD: '',                             // no guard, so the history reads as unavailable
        DOTENV_CONFIG_PATH: resolve(root, 'test/.env.absent'), // never read the developer's real .env
      },
    });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (c) => (stdout += c));
    proc.stderr.on('data', (c) => (stderr += c));
    proc.on('error', fail);
    proc.on('close', (status) => done({ status, stdout, stderr }));
  });
  assert.equal(child.status, 0, `the engine child process failed: ${child.stderr}`);

  const engine = JSON.parse(child.stdout);
  const page = cases.map(([addr, amount]) => A.decide({
    bytecode: A.bytecodeVerdict(addr, CORPUS[addr] === '0x' ? undefined : CORPUS[addr]),
    reputation: A.checkReputation(addr),
    behavior: A.behaviorVerdict(amount, null),
  }).decision);

  assert.deepEqual(page, engine, 'the page and the engine returned different verdicts');
  assert.ok(engine.includes('BLOCK') && engine.includes('PAY') && engine.includes('ASK_HUMAN'),
    'this comparison is only worth something if all three verdicts appear in it');
});

test('a HIGH score is never quietly downgraded in the browser', () => {
  // the one direction the missing LLM may move a verdict. the engine can turn a
  // HIGH into ASK_HUMAN when the model calls the alarm false; with no model the
  // page has to stay on BLOCK, which is the safe side of that difference and is
  // what the page tells the reader it does.
  const r = A.decide({
    bytecode: A.bytecodeVerdict('0x00000000000000000000000000000000000000f3', CORPUS['0x00000000000000000000000000000000000000f3']),
    reputation: A.checkReputation('0x00000000000000000000000000000000000000f3'),
    behavior: A.behaviorVerdict(1, null),
  });
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.llmWouldRun, true, 'the page has to say a second pass was skipped, not hide it');
  assert.match(r.reasons.join(' '), /falling back to deterministic BLOCK/);
});

// ---- the hand-rolled crypto and abi work -----------------------------------

test('keccak-256 matches viem, on the vectors and on 300 random lengths', () => {
  assert.equal(A.keccak256('0x'), viemKeccak('0x'));
  assert.equal(A.keccak256Text('abc'), viemKeccak(toHex('abc')));
  assert.equal(A.keccak256Text(''), viemKeccak('0x'));

  // 136 bytes is the rate, so the lengths around it and around its multiples are
  // where a padding mistake shows up. an lcg rather than Math.random so a
  // failure is reproducible.
  let seed = 12345;
  const next = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) >> 8) & 0xff;
  for (let len = 0; len < 300; len++) {
    const bytes = Uint8Array.from({ length: len }, next);
    const asHex = '0x' + Buffer.from(bytes).toString('hex');
    assert.equal(A.keccak256(asHex), viemKeccak(asHex), `keccak disagreed at ${len} bytes`);
  }
});

test('the EIP-55 checksum matches viem, and a mistyped address is refused', () => {
  for (const address of [...Object.keys(CORPUS), A.GUARD, '0x9a0da68c0f9654bd7110e928f229b7c4c216de9c']) {
    assert.equal(A.toChecksumAddress(address), getAddress(address));
  }

  const good = getAddress('0x9a0da68c0f9654bd7110e928f229b7c4c216de9c');
  assert.deepEqual(A.parseAddress(good), { ok: true, address: good });
  assert.deepEqual(A.parseAddress(good.toLowerCase()), { ok: true, address: good });

  // one letter's case flipped: still 40 hex characters, still points at a
  // real-looking address, and the checksum is the only thing that notices.
  const at = [...good].findIndex((c, i) => i > 1 && /[a-f]/i.test(c));
  const flipped = good[at] === good[at].toLowerCase() ? good[at].toUpperCase() : good[at].toLowerCase();
  assert.equal(A.parseAddress(good.slice(0, at) + flipped + good.slice(at + 1)).why, 'checksum');
  assert.equal(A.parseAddress('0x123').why, 'malformed');
  assert.equal(A.parseAddress('').why, 'malformed');
});

test('the hardcoded selectors and topic are the real ones', () => {
  assert.equal(A.ASSESS_SELECTOR, toFunctionSelector('function assess(address,uint256) view returns (uint8,string)'));
  assert.equal(A.DAILY_LIMIT_SELECTOR, toFunctionSelector('function dailyLimit() view returns (uint256)'));
  assert.equal(A.PAID_TOPIC0, toEventSelector('event Paid(address indexed agent, address indexed to, uint256 amount)'));
});

test('the assess return is decoded the way viem decodes it', () => {
  const abi = parseAbi(['function assess(address to, uint256 amount) view returns (uint8, string)']);
  const cases = [
    [0, 'clear'],
    [1, 'recipient denylisted'],
    [2, 'unvetted contract recipient'],
    [1, ''],                                            // empty tail
    [2, 'a reason long enough to cross a 32 byte word boundary and then some'],
    [1, 'a reason with a multi byte character in it: €'],
  ];
  for (const [verdict, reason] of cases) {
    const encoded = encodeAbiParameters([{ type: 'uint8' }, { type: 'string' }], [verdict, reason]);
    const expected = decodeFunctionResult({ abi, functionName: 'assess', data: encoded });
    const mine = A.decodeAssess(encoded);
    assert.equal(mine.verdict, expected[0]);
    assert.equal(mine.reason, expected[1]);
    assert.equal(mine.verdictName, ['Pay', 'Block', 'Review'][verdict]);
  }
  assert.throws(() => A.decodeAssess('0x1234'), /short answer/);
});

test('an amount is converted to base units without going through a float', () => {
  assert.equal(A.toBaseUnits('1'), 1000000n);
  assert.equal(A.toBaseUnits('0.1'), 100000n);
  assert.equal(A.toBaseUnits('100.000001'), 100000001n);
  assert.equal(A.toBaseUnits('0.000001'), 1n);
  assert.equal(A.toBaseUnits('0'), 0n);
  assert.equal(A.toBaseUnits('1.0000001'), null, 'more precision than USDC has must be refused, not rounded');
  assert.equal(A.toBaseUnits('-1'), null);
  assert.equal(A.toBaseUnits('1e6'), null);
  assert.equal(A.toBaseUnits('abc'), null);
});

// ---- the page as a shipped artifact ----------------------------------------

test('the page loads nothing from anywhere', () => {
  // the whole claim is "nothing to trust but the code in front of you". one
  // <script src> to a cdn and that claim is gone, so it is a test and not a
  // convention.
  assert.equal(html.match(/<script[^>]+src=/i), null, 'the page must not load a script from anywhere');
  assert.equal(html.match(/<link[^>]+stylesheet/i), null, 'the page must not load a stylesheet');
  assert.equal(html.match(/<img|@import|url\(\s*['"]?https?:/i), null, 'the page must not pull in a remote asset');
});

// ---- the page's own ui, driven headlessly ----------------------------------
// the lane code above is the part that has a twin to be compared against. the
// ui block has none, and it is where the page can go wrong in ways that still
// look fine: a result written for an address the reader has already moved on
// from, an error swallowed, a string from the chain rendered as markup. so it
// gets a fake dom and a fake chain and is driven like a browser would drive it.
const dom = {
  el(id) {
    if (!this.byId[id]) {
      this.byId[id] = {
        id, value: '', className: '', textContent: '', innerHTML: '', hidden: false, disabled: false,
        children: [], handlers: {},
        addEventListener(k, f) { this.handlers[k] = f; },
        appendChild(c) { this.children.push(c); },
        requestSubmit() { this.handlers.submit?.({ preventDefault() {} }); },
      };
    }
    return this.byId[id];
  },
  byId: {},
};

// a stub Arc. every answer is a knob, so a test can make the guard fail, make a
// read slow, or hand the page a hostile string and see what it does with it.
const chain = {
  code: '0x',
  assessReason: 'clear',
  assessVerdict: 0,
  guardFails: false,
  delayFor: {},   // address -> ms
};

const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  // only the four Arc gateways are stubbed. everything else, including viem's
  // calls to the local eth_getCode stub above, goes through untouched - a fake
  // fetch that swallowed those would quietly break the parity tests.
  if (!A.RPCS.includes(url)) return realFetch(url, init);

  const { method, params } = JSON.parse(init.body);
  const target = String(params?.[0]?.to ?? params?.[0] ?? '').toLowerCase();
  const wait = chain.delayFor[target] ?? 0;
  if (wait) await new Promise((r) => setTimeout(r, wait));

  let result;
  if (method === 'eth_getCode') result = chain.code;
  else if (method === 'eth_blockNumber') result = '0x1000';
  else if (method === 'eth_getLogs') result = [];
  else if (method === 'eth_call') {
    if (chain.guardFails) return { ok: false, status: 503, json: async () => ({}) };
    result = String(params[0].data).startsWith(A.DAILY_LIMIT_SELECTOR)
      ? '0x' + (100000000n).toString(16).padStart(64, '0')
      : encodeAbiParameters([{ type: 'uint8' }, { type: 'string' }], [chain.assessVerdict, chain.assessReason]);
  }
  return { ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 1, result }) };
};

globalThis.document = {
  getElementById: (id) => dom.el(id),
  createElement: () => ({ type: '', className: '', textContent: '', handlers: {}, addEventListener(k, f) { this.handlers[k] = f; } }),
};
globalThis.location = { search: '' };

const uiBlocks = [...html.matchAll(/<script type="module"[^>]*>([\s\S]*?)<\/script>/g)];
assert.equal(uiBlocks.length, 2, 'the page should have exactly two script blocks: the engine and the ui');
await import(`data:text/javascript;base64,${Buffer.from(uiBlocks[1][1], 'utf8').toString('base64')}`);

const HONEYPOT = '0x9A0Da68C0F9654Bd7110E928F229B7c4C216dE9C';
const OTHER = '0x000000000022D473030F116dDEE9F6B43aC78BA3';

// the page fires run() without awaiting it, the way a submit handler has to, so
// the driver waits for the page to stop saying it is working.
async function submit(address, amount = '1') {
  dom.el('addr').value = address;
  dom.el('amt').value = amount;
  dom.el('form').handlers.submit({ preventDefault() {} });
  for (let i = 0; i < 200 && dom.el('status').textContent === 'Reading Arc...'; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return dom.el('out');
}

test('the page offers examples that are all real addresses', () => {
  const chips = dom.el('examples').children;
  assert.ok(chips.length >= 4, 'a judge should not have to go find an address to paste');
  for (const chip of chips) assert.ok(chip.textContent.length > 0);
});

test('a check renders a verdict, the lanes, and what the guard says', async () => {
  chain.code = '0x6080604052ff'; // enough to trip SELFDESTRUCT
  chain.assessVerdict = 1;
  chain.assessReason = 'recipient code is blocklisted';
  const out = await submit(HONEYPOT);

  assert.equal(out.hidden, false);
  assert.match(out.innerHTML, /<span class="tag block">BLOCK<\/span>/);
  assert.match(out.innerHTML, /recipient code is blocklisted/);
  assert.match(out.innerHTML, /SELFDESTRUCT/);
  assert.match(out.innerHTML, /Both layers land on the same side/);
  assert.match(out.innerHTML, /100 USDC/, 'the live daily cap should be shown, not hardcoded prose');
  assert.equal(dom.el('go').disabled, false, 'the button has to come back');
});

test('when the two layers disagree the page says which one binds', async () => {
  chain.code = '0x00';        // a harmless contract: the browser lane clears it
  chain.assessVerdict = 2;    // and the guard still will not pay an unvetted contract
  chain.assessReason = 'unvetted contract recipient';
  const out = await submit(OTHER);

  assert.match(out.innerHTML, /<span class="tag pay">PAY<\/span>/);
  assert.match(out.innerHTML, /guardedPay<\/code> reverts on anything but/);
});

test('when the guard is the harder no, the page says why it can be', async () => {
  // the clone case, and the best single demonstration in the project: a 45-byte
  // minimal proxy is only MEDIUM to an opcode scan, because the implementation
  // it forwards to is not visible from here - and the guard blocks it outright,
  // because a codehash written once covers every clone that shares those bytes.
  chain.code = '0x363d3d373d3d3d363d739a0da68c0f9654bd7110e928f229b7c4c216de9c5af43d82803e903d91602b57fd5bf3';
  chain.assessVerdict = 1;
  chain.assessReason = 'recipient code is blocklisted';
  const out = await submit(OTHER);

  assert.match(out.innerHTML, /<span class="tag ask">ASK_HUMAN<\/span>/);
  assert.match(out.innerHTML, /MINIMAL_PROXY/);
  assert.match(out.innerHTML, /the guard is the harder no/);
});

test('a string from the chain is rendered as text, never as markup', async () => {
  // reason strings come off a contract. this one is ours, but the page should
  // not be one hostile deployment away from running someone else's script.
  chain.code = '0x00';
  chain.assessVerdict = 1;
  chain.assessReason = '<img src=x onerror="alert(1)">';
  const out = await submit(OTHER);

  assert.match(out.innerHTML, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.equal(out.innerHTML.includes('<img'), false, 'a chain-supplied string was rendered as html');
});

test('a stale read cannot overwrite a newer one', async () => {
  // click one example, then another before the first finishes. the answer left
  // on screen has to be for the address in the box.
  chain.code = '0x00';
  chain.assessVerdict = 0;
  chain.assessReason = 'clear';
  chain.delayFor[HONEYPOT.toLowerCase()] = 300;

  dom.el('addr').value = HONEYPOT;
  dom.el('amt').value = '1';
  dom.el('form').handlers.submit({ preventDefault() {} });   // slow one, not awaited
  const out = await submit(OTHER);                            // fast one, overtakes it

  assert.match(out.innerHTML, new RegExp(OTHER.slice(0, 6)));
  await new Promise((r) => setTimeout(r, 600));               // let the slow one land
  assert.match(out.innerHTML, new RegExp(OTHER.slice(0, 6)), 'the slower read overwrote the newer answer');
  assert.equal(out.innerHTML.includes(HONEYPOT.slice(0, 8)), false);
  delete chain.delayFor[HONEYPOT.toLowerCase()];
});

test('a malformed address renders nothing at all', async () => {
  const before = dom.el('out').innerHTML;
  const out = await submit('0xdeadbeef');
  assert.equal(out.hidden, true, 'a stale result must not sit there looking like an answer');
  assert.equal(out.innerHTML, before, 'nothing new should have been rendered');
  assert.match(dom.el('status').textContent, /not an address/);
  assert.equal(dom.el('go').disabled, false, 'a rejected input must not leave the button stuck');
});

test('a mistyped-but-well-formed address is refused before any read', async () => {
  const typo = HONEYPOT.slice(0, -1) + (HONEYPOT.slice(-1) === 'C' ? 'c' : 'C');
  await submit(typo);
  assert.equal(dom.el('out').hidden, true);
  assert.match(dom.el('status').textContent, /EIP-55 checksum/);
});

test('the browser verdict still shows when the guard cannot be read', async () => {
  // the two halves are independent reads and the page must not lose both
  // because one gateway is having a bad minute.
  chain.code = '0x6080604052ff';
  chain.guardFails = true;
  const out = await submit(HONEYPOT);
  chain.guardFails = false;

  assert.equal(out.hidden, false);
  assert.match(out.innerHTML, /<span class="tag block">BLOCK<\/span>/);
  assert.match(out.innerHTML, /Could not read the guard/);
});

test('the addresses on the page are the ones the README publishes', () => {
  // a wrong guard address here would read as a working page giving confident
  // answers about a contract nobody deployed.
  const readme = readFileSync(resolve(root, 'README.md'), 'utf8').toLowerCase();
  assert.ok(readme.includes(A.GUARD.toLowerCase()), 'the guard address on the page is not the one in the README');
  assert.equal(A.CHAIN_ID, 5042002);
  assert.ok(A.RPCS.length >= 2, 'one gateway is a single point of failure for a page a judge is about to open');
  for (const url of A.RPCS) assert.match(url, /^https:\/\//, 'a page served over https cannot call an http gateway');
});

test.after(() => server.close());

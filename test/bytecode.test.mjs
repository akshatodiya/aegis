// offline tests for the bytecode lane's metadata handling. no anvil and no
// network: the pure trim is asserted directly, and the end-to-end path runs
// against a stub eth_getCode that serves crafted runtime code.
//
// what these are guarding against: the trim used to trust the recipient's own
// trailing length field plus a single 0xa2 marker byte to decide where to stop
// scanning. that let a contract declare its malicious tail to be "metadata" and
// walk straight past the lane - a false negative, which is the one direction a
// firewall can't fail in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

const hex = (bytes) => '0x' + Buffer.from(bytes).toString('hex');

// what solc actually appends: a 2-pair cbor map, "ipfs" -> 34-byte hash and
// "solc" -> 3-byte version, then a 2-byte length. 51 bytes of blob here.
function solcMetadata(hashByte = 0x11) {
  return [
    0xa2,
    0x64, 0x69, 0x70, 0x66, 0x73, // text(4) "ipfs"
    0x58, 0x22, ...Array(34).fill(hashByte), // bytes(34)
    0x64, 0x73, 0x6f, 0x6c, 0x63, // text(4) "solc"
    0x43, 0x00, 0x08, 0x1c, // bytes(3) 0.8.28
    0x00, 0x33, // blob length = 51
  ];
}

// 20 bytes of harmless body with no dangling push, then real-shaped metadata
const BODY = Array(20).fill(0x00);
const HONEST = hex([...BODY, ...solcMetadata()]);

// idx 0 PUSH1 09 / JUMP -> JUMPDEST at 9, SELFDESTRUCT at 10. the tail declares
// itself 6 bytes of metadata and opens with 0xa2, but 0x5b is not a cbor item
// solc ever emits, so the blob doesn't account for its own declared length.
const NAIVE = hex([0x60, 0x09, 0x56, 0, 0, 0, 0, 0, 0xa2, 0x5b, 0xff, 0, 0, 0, 0x00, 0x06]);

// the same trick by someone who read the fix: a well-formed 2-pair cbor map
// that ends exactly on the length field, hiding the SELFDESTRUCT inside a byte
// string. structurally valid - caught only because the body jumps into it.
const CRAFTED = hex([
  0x60, 0x0c, 0x56, 0, 0, 0, 0, 0,
  0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
  0x00, 0x0d,
]);

const ADDR = {
  honest: '0x00000000000000000000000000000000000000a0',
  naive: '0x00000000000000000000000000000000000000b0',
  crafted: '0x00000000000000000000000000000000000000c0',
};
const CODE = { [ADDR.honest]: HONEST, [ADDR.naive]: NAIVE, [ADDR.crafted]: CRAFTED };

// a stub eth_getCode, so the lane's real network path runs with no anvil
const server = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    const { id, method, params } = JSON.parse(raw);
    let result = '0x0';
    if (method === 'eth_getCode') result = CODE[String(params[0]).toLowerCase()] ?? '0x';
    if (method === 'eth_chainId') result = '0xaa36a7';
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));

// config.js reads these once, at import time - so the env has to be set before
// the lane (and through it, config) is loaded, and the import has to be the
// only one in this file. a second import returns the same cached module.
process.env.CHAIN = 'sepolia';
process.env.RPC_URL = `http://127.0.0.1:${server.address().port}`;
const { stripMetadata, checkBytecode } = await import('../src/lanes/bytecode.js');

test('genuine solc metadata is still trimmed, at the right boundary', () => {
  const { body, hidden } = stripMetadata(HONEST);
  assert.equal(body.length / 2 - 1, BODY.length, 'body should be exactly the code before the blob');
  assert.equal(hidden, false);
});

test('a trailer that is not valid cbor is not trusted as metadata', () => {
  const { body, hidden } = stripMetadata(NAIVE);
  assert.equal(body, NAIVE, 'nothing may be cut - the whole code gets scanned');
  assert.equal(hidden, false, 'this one is just untrimmed, not proven executable');
});

test('valid cbor the code jumps into is flagged as hidden code', () => {
  const { body, hidden } = stripMetadata(CRAFTED);
  assert.equal(body, CRAFTED, 'nothing may be cut');
  assert.equal(hidden, true, 'a jump into the blob means it is code, not a hash');
});

// the same hidden-code trick, but reaching the blob with every push width
// there is. the first version of this check only looked at PUSH1-PUSH4, so a
// PUSH5 carrying the identical zero-padded target walked straight through it.
//
//   idx 0      PUSHn <target, big-endian, zero-padded to n bytes>
//   idx 1+n    JUMP
//   idx 2+n    the same well-formed CBOR blob, JUMPDEST at +4, SELFDESTRUCT at +5
function craftedWithPush(n) {
  const start = n + 2;
  const target = start + 4; // the JUMPDEST inside the blob
  // big-endian, zero-padded to n bytes. built by division, not by `>>`, which
  // is a 32-bit operation in JS and silently wraps once n gets past 4.
  const imm = new Array(n).fill(0);
  for (let k = n - 1, t = target; k >= 0; k--, t = Math.floor(t / 256)) imm[k] = t & 0xff;
  return hex([
    0x60 + n - 1, ...imm, 0x56,
    0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x0d,
  ]);
}

test('the blob is caught however wide the push that reaches it', () => {
  for (let n = 1; n <= 32; n++) {
    const { body, hidden } = stripMetadata(craftedWithPush(n));
    assert.equal(hidden, true, `PUSH${n} reached the blob without being flagged`);
    assert.equal(body, craftedWithPush(n), `PUSH${n} still got its blob trimmed away`);
  }
});

test('a push whose high bytes rule out an offset is not treated as a jump', () => {
  // PUSH5 0xff00000000 is a constant, not a code offset - a contract that big
  // cannot exist. flagging it would be a false positive on honest code. the
  // blob here is deliberately valid CBOR, so this really does test the
  // high-byte rejection and not just a malformed trailer.
  const code = hex([
    0x64, 0xff, 0x00, 0x00, 0x00, 0x00, 0x56,
    0xa2, 0x61, 0x61, 0x43, 0x5b, 0xff, 0x00, 0x61, 0x62, 0x43, 0x00, 0x00, 0x00,
    0x00, 0x0d,
  ]);
  const { body, hidden } = stripMetadata(code);
  assert.equal(hidden, false);
  assert.notEqual(body, code, 'a valid blob nothing jumps into should still be trimmed');
});

test('a blob length pointing outside the code is ignored', () => {
  const silly = hex([0x00, 0x00, 0xff, 0xff]); // declares 65535 bytes of metadata
  const { body, hidden } = stripMetadata(silly);
  assert.equal(body, silly);
  assert.equal(hidden, false);
});

// --- end to end, through the real checkBytecode against the stub ---

test('a hidden SELFDESTRUCT behind a faked trailer still scores HIGH', async () => {
  const r = await checkBytecode(ADDR.naive);
  assert.equal(r.level, 'HIGH');
  assert.ok(r.hits.SELFDESTRUCT, 'the opcode past the fake boundary must be counted');
});

test('a hidden SELFDESTRUCT behind valid cbor scores HIGH and names the tail', async () => {
  const r = await checkBytecode(ADDR.crafted);
  assert.equal(r.level, 'HIGH');
  assert.ok(r.hits.SELFDESTRUCT);
  assert.ok(r.hits.HIDDEN_CODE, 'the executable "metadata" blob is itself a finding');
});

test('an honest contract is not dragged up by its own metadata bytes', async () => {
  const r = await checkBytecode(ADDR.honest);
  assert.equal(r.level, 'LOW');
  assert.equal(r.score, 0);
  assert.equal(r.isContract, true);
});

test.after(() => server.close());

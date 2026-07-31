// end-to-end tests for AegisAuditLog against a local anvil node, same shape as
// guard.test.mjs: spin up a node, deploy, drive every path through viem.
//
// what these are really checking is that the log cannot say something that did
// not happen. an outsider can't write to it, a reporter can't record a PAY,
// nothing lands without a reason, and a merchant can't choose how big an entry
// is. a receipt drawer that accepts anything is worse than no receipts, because
// it looks like evidence.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  createPublicClient, createWalletClient, http, keccak256, toHex, parseEventLogs,
  ContractFunctionRevertedError,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { compileContract } from '../src/compile.js';

// a port of its own: node --test runs files in parallel, and guard.test.mjs has
// anvil's default 8545. sharing one node would mean sharing a nonce space with
// another suite's transactions.
const PORT = 8546;
const RPC = `http://127.0.0.1:${PORT}`;

// anvil's deterministic dev keys
const PK = {
  owner:    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // owner + reporter
  outsider: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', // authorized for nothing
};
const owner = privateKeyToAccount(PK.owner);
const outsider = privateKeyToAccount(PK.outsider);
const MERCHANT = '0x0000000000000000000000000000000000000011';

const pub = createPublicClient({ chain: foundry, transport: http(RPC) });
const asOwner = createWalletClient({ account: owner, chain: foundry, transport: http(RPC) });
const asOutsider = createWalletClient({ account: outsider, chain: foundry, transport: http(RPC) });

const LOG = compileContract('AegisAuditLog.sol', 'AegisAuditLog');
const V = { BLOCK: 0, ASK_HUMAN: 1 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let anvil;
let auditLog; // fresh per test

// same PATH problem as guard.test.mjs: foundryup only wires ~/.foundry/bin into
// interactive shells, so look there before deciding anvil isn't installed.
function anvilCommand() {
  const local = join(homedir(), '.foundry', 'bin', 'anvil');
  return existsSync(local) ? local : 'anvil';
}

before(async () => {
  const cmd = anvilCommand();
  let spawnError = null;
  anvil = spawn(cmd, ['--silent', '--port', String(PORT)], { stdio: 'ignore' });
  anvil.on('error', (err) => { spawnError = err; });

  for (let i = 0; i < 60; i++) {
    if (spawnError) break;
    try { await pub.getBlockNumber(); return; } catch { await sleep(100); }
  }
  if (spawnError?.code === 'ENOENT') {
    throw new Error(
      `could not run anvil (tried "${cmd}").\n` +
      '  install it:  curl -L https://foundry.paradigm.xyz | bash && foundryup\n' +
      '  already installed? add it to PATH for this shell:\n' +
      '    export PATH="$HOME/.foundry/bin:$PATH"',
    );
  }
  throw new Error('anvil did not come up');
});

after(() => { if (anvil) anvil.kill(); });

async function send(functionName, args, account = owner) {
  const wallet = account === owner ? asOwner : asOutsider;
  const hash = await wallet.writeContract({
    address: auditLog, abi: LOG.abi, functionName, args, account,
  });
  return pub.waitForTransactionReceipt({ hash });
}

const read = (functionName, args = []) =>
  pub.readContract({ address: auditLog, abi: LOG.abi, functionName, args });

async function expectRevert(run, needle) {
  try {
    await run();
  } catch (err) {
    const revert = typeof err.walk === 'function'
      ? err.walk((e) => e instanceof ContractFunctionRevertedError)
      : null;
    const parts = [err.shortMessage || err.message || String(err)];
    if (revert?.data) {
      parts.push(revert.data.errorName ?? '');
      // ReasonTooLong carries two uint256s, and JSON.stringify throws on a
      // BigInt - which would swallow the assertion and report a TypeError.
      parts.push(JSON.stringify(revert.data.args ?? [], (_k, v) => (typeof v === 'bigint' ? String(v) : v)));
    }
    const hay = parts.join(' | ');
    assert.ok(hay.includes(needle), `expected revert with "${needle}", got: ${hay}`);
    return;
  }
  assert.fail(`expected a revert containing "${needle}"`);
}

// fresh contract per test so the id counter never leaks across
beforeEach(async () => {
  const hash = await asOwner.deployContract({ ...LOG, account: owner });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  auditLog = receipt.contractAddress;
  await send('setReporter', [owner.address, true]);
});

test('a refusal is recorded with who, how much, why and which verdict', async () => {
  const reason = 'verdict BLOCK on payTo 0x..11 - recipient denylisted';
  const receipt = await send('logRefusal', [MERCHANT, 50_000n, V.BLOCK, reason]);

  const [entry] = parseEventLogs({ abi: LOG.abi, eventName: 'Refused', logs: receipt.logs });
  assert.equal(entry.args.reporter.toLowerCase(), owner.address.toLowerCase());
  assert.equal(entry.args.recipient.toLowerCase(), MERCHANT.toLowerCase());
  assert.equal(entry.args.amount, 50_000n);
  assert.equal(entry.args.verdict, V.BLOCK);
  assert.equal(entry.args.reason, reason);
  assert.equal(entry.args.id, 1n);
  // the hash is what makes "show me every refusal for this reason" one indexed
  // query instead of a scan of every entry ever written.
  assert.equal(entry.args.reasonHash, keccak256(toHex(reason)));
  assert.equal(await read('totalRefusals'), 1n);
});

test('a stranger cannot write to the log', async () => {
  // the point of the gate: entries are only worth reading if the set of writers
  // is known. anyone could spam a public log with refusals we never made.
  await expectRevert(
    () => pub.simulateContract({
      address: auditLog, abi: LOG.abi, functionName: 'logRefusal',
      args: [MERCHANT, 1n, V.BLOCK, 'i made this up'], account: outsider,
    }),
    'NotReporter',
  );
});

test('the owner can revoke a reporter, and the writes stop', async () => {
  await send('logRefusal', [MERCHANT, 1n, V.BLOCK, 'first']);
  await send('setReporter', [owner.address, false]);

  await expectRevert(
    () => pub.simulateContract({
      address: auditLog, abi: LOG.abi, functionName: 'logRefusal',
      args: [MERCHANT, 1n, V.BLOCK, 'second'], account: owner,
    }),
    'NotReporter',
  );
  assert.equal(await read('totalRefusals'), 1n, 'the revoked write must not have counted');
});

test('only the owner can authorize reporters', async () => {
  for (const [functionName, args] of [
    ['setReporter', [outsider.address, true]],
    ['transferOwnership', [outsider.address]],
  ]) {
    await expectRevert(
      () => pub.simulateContract({ address: auditLog, abi: LOG.abi, functionName, args, account: outsider }),
      'NotOwner',
    );
  }
});

test('ids are consecutive, so a reader can tell which entries it missed', async () => {
  // this is what totalRefusals is for. a query covers a block window and a
  // gateway can cap what it returns, so "I found two" and "there are two" are
  // different claims - the counter and the ids are how a reader tells them apart.
  const ids = [];
  for (const reason of ['one', 'two', 'three']) {
    const receipt = await send('logRefusal', [MERCHANT, 1n, V.BLOCK, reason]);
    const [entry] = parseEventLogs({ abi: LOG.abi, eventName: 'Refused', logs: receipt.logs });
    ids.push(entry.args.id);
  }
  assert.deepEqual(ids, [1n, 2n, 3n]);
  assert.equal(await read('totalRefusals'), 3n);
});

test('a PAY cannot be recorded here at all', async () => {
  // the enum has two members on purpose: this is a refusal log by construction,
  // not by convention, and the cost argument for logging refusals only ("they
  // are rare") depends on it staying that way. verdict 2 dies in the decoder.
  await expectRevert(
    () => pub.simulateContract({
      address: auditLog, abi: LOG.abi, functionName: 'logRefusal',
      args: [MERCHANT, 1n, 2, 'this was allowed'], account: owner,
    }),
    'revert',
  );
});

test('an entry with no reason is refused', async () => {
  // it would look like a record while carrying nothing anyone could check.
  await expectRevert(
    () => pub.simulateContract({
      address: auditLog, abi: LOG.abi, functionName: 'logRefusal',
      args: [MERCHANT, 1n, V.BLOCK, ''], account: owner,
    }),
    'EmptyReason',
  );
});

test('the merchant does not get to choose how big an entry is', async () => {
  // reasons quote the wire, and the demanded amount only had to be digits to get
  // this far - so without a ceiling here a 402 could name a 100kB price and make
  // the receipt cost more than the payment. 256 bytes exactly is fine, one more
  // is not, and src/audit.js trims to the same number before it ever sends.
  const max = await read('MAX_REASON_BYTES');
  assert.equal(max, 256n);

  await send('logRefusal', [MERCHANT, 1n, V.BLOCK, 'a'.repeat(256)]);
  assert.equal(await read('totalRefusals'), 1n);

  await expectRevert(
    () => pub.simulateContract({
      address: auditLog, abi: LOG.abi, functionName: 'logRefusal',
      args: [MERCHANT, 1n, V.BLOCK, 'a'.repeat(257)], account: owner,
    }),
    'ReasonTooLong',
  );
});

test('the zero address is a valid recipient - some refusals never name one', async () => {
  // "no acceptable payment option" is refused before anyone is named. the log
  // has to be able to say that rather than force an invented address.
  const receipt = await send(
    'logRefusal',
    ['0x0000000000000000000000000000000000000000', 0n, V.ASK_HUMAN, 'no acceptable payment option'],
  );
  const [entry] = parseEventLogs({ abi: LOG.abi, eventName: 'Refused', logs: receipt.logs });
  assert.equal(entry.args.verdict, V.ASK_HUMAN);
  assert.equal(entry.args.amount, 0n);
});

test('ownership transfer is two-step, same as the guard', async () => {
  await send('transferOwnership', [outsider.address]);
  assert.equal((await read('owner')).toLowerCase(), owner.address.toLowerCase());
  assert.equal((await read('pendingOwner')).toLowerCase(), outsider.address.toLowerCase());

  await expectRevert(
    () => pub.simulateContract({ address: auditLog, abi: LOG.abi, functionName: 'acceptOwnership', account: owner }),
    'NotOwner',
  );

  await send('acceptOwnership', [], outsider);
  assert.equal((await read('owner')).toLowerCase(), outsider.address.toLowerCase());
});

// end-to-end tests for AegisGuard against a local anvil node.
// spins up anvil, deploys a mock USDC + the guard + the honeypot villain, and
// drives every policy path through viem - the same library the agent uses. no
// fork, no testnet, no keys: just `npm test`.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  createPublicClient, createWalletClient, http, parseUnits, keccak256, parseEventLogs,
  ContractFunctionRevertedError,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';
import { compileContract } from '../src/compile.js';
import { REFUSAL, guardReasonCode } from '../src/refusals.js';

const RPC = 'http://127.0.0.1:8545';

// anvil's deterministic dev keys
const PK = {
  owner:    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', // owner + treasury + agent
  outsider: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d', // not an agent
  bob:      '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a', // a good EOA recipient
};
const owner = privateKeyToAccount(PK.owner);
const outsider = privateKeyToAccount(PK.outsider);
const bob = privateKeyToAccount(PK.bob).address;
// stand-in for the agent's x402 float wallet (a plain EOA the treasury refills)
const floatWallet = privateKeyToAccount('0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a').address;

const pub = createPublicClient({ chain: foundry, transport: http(RPC) });
const asOwner = createWalletClient({ account: owner, chain: foundry, transport: http(RPC) });
const asOutsider = createWalletClient({ account: outsider, chain: foundry, transport: http(RPC) });

const usd = (n) => parseUnits(String(n), 6);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const MOCK = compileContract('MockERC20.sol', 'MockERC20');
const GUARD = compileContract('AegisGuard.sol', 'AegisGuard');
const HONEY = compileContract('HoneypotVault.sol', 'HoneypotVault');

let anvil;
let usdc, guard, honeypot; // deployed addresses, fresh per test

// foundryup only wires ~/.foundry/bin into interactive shell profiles, so a
// non-interactive shell (CI, `sh -c`, some editors) can have anvil installed and
// still not find it on PATH. look there before giving up, and tell the two
// failures apart - "not installed" and "installed but invisible" want different
// fixes, and both used to surface as the same misleading "did not come up".
function anvilCommand() {
  const local = join(homedir(), '.foundry', 'bin', 'anvil');
  return existsSync(local) ? local : 'anvil';
}

before(async () => {
  const cmd = anvilCommand();
  let spawnError = null;
  anvil = spawn(cmd, ['--silent'], { stdio: 'ignore' });
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

async function deploy(artifact, args = []) {
  const hash = await asOwner.deployContract({ ...artifact, args, account: owner });
  const receipt = await pub.waitForTransactionReceipt({ hash });
  return receipt.contractAddress;
}

async function send(address, abi, functionName, args, account = owner) {
  const wallet = account === owner ? asOwner : asOutsider;
  const hash = await wallet.writeContract({ address, abi, functionName, args, account });
  return pub.waitForTransactionReceipt({ hash });
}

async function assess(to, amount) {
  const [verdict, reason] = await pub.readContract({
    address: guard, abi: GUARD.abi, functionName: 'assess', args: [to, usd(amount)],
  });
  return { verdict: Number(verdict), reason }; // 0 Pay, 1 Block, 2 Review
}

// simulate a call and assert it reverts. `needle` is matched against the
// decoded custom error name and its args (e.g. Denied's reason string), with
// the raw message as a fallback.
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
      // a revert arg can be a uint256, and JSON.stringify throws on a BigInt -
      // which would swallow the assertion and report a TypeError instead.
      parts.push(JSON.stringify(revert.data.args ?? [], (_k, v) => (typeof v === 'bigint' ? String(v) : v)));
    }
    const hay = parts.join(' | ');
    assert.ok(hay.includes(needle), `expected revert with "${needle}", got: ${hay}`);
    return;
  }
  assert.fail(`expected a revert containing "${needle}"`);
}

// fresh contracts before each test so spend accounting etc. never leaks across
beforeEach(async () => {
  usdc = await deploy(MOCK);
  guard = await deploy(GUARD, [usdc, owner.address, usd(100)]); // daily limit 100
  honeypot = await deploy(HONEY);

  // fund the treasury and wire the guard up
  await send(usdc, MOCK.abi, 'mint', [owner.address, usd(1_000_000)]);
  await send(usdc, MOCK.abi, 'approve', [guard, usd(1_000_000)]);
  await send(guard, GUARD.abi, 'setAgent', [owner.address, true]);
});

const V = { PAY: 0, BLOCK: 1, REVIEW: 2 };

test('assess: a plain EOA within the limit is PAY', async () => {
  const { verdict, reason } = await assess(bob, 10);
  assert.equal(verdict, V.PAY);
  assert.equal(reason, 'clear');
});

test('assess: an unvetted contract recipient is REVIEW', async () => {
  const { verdict, reason } = await assess(honeypot, 10);
  assert.equal(verdict, V.REVIEW);
  assert.equal(reason, 'unvetted contract recipient');
});

test('assess: a denylisted recipient is BLOCK', async () => {
  await send(guard, GUARD.abi, 'setDenylisted', [bob, true]);
  const { verdict, reason } = await assess(bob, 10);
  assert.equal(verdict, V.BLOCK);
  assert.equal(reason, 'recipient denylisted');
});

test('guardedPay: an allowed payment moves USDC and emits Paid', async () => {
  const before = await pub.readContract({ address: usdc, abi: MOCK.abi, functionName: 'balanceOf', args: [bob] });
  const receipt = await send(guard, GUARD.abi, 'guardedPay', [bob, usd(10)]);
  const after = await pub.readContract({ address: usdc, abi: MOCK.abi, functionName: 'balanceOf', args: [bob] });
  assert.equal(after - before, usd(10));

  const [paid] = parseEventLogs({ abi: GUARD.abi, eventName: 'Paid', logs: receipt.logs });
  assert.equal(paid.args.to.toLowerCase(), bob.toLowerCase());
  assert.equal(paid.args.amount, usd(10));
});

test('guardedPay: a non-agent caller is rejected', async () => {
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [bob, usd(10)], account: outsider }),
    'NotAgent',
  );
});

// ---- the kill switch ----
// the tests above cover a caller who was never an agent. these cover revoking
// one that is, which is the thing an operator actually does when the agent
// starts behaving oddly, and the ordering that makes it worth doing.

test('revoking a live agent stops the payment that worked a moment ago', async () => {
  await send(guard, GUARD.abi, 'guardedPay', [bob, usd(10)]);

  await send(guard, GUARD.abi, 'setAgent', [owner.address, false]);
  assert.equal(
    await pub.readContract({ address: guard, abi: GUARD.abi, functionName: 'isAgent', args: [owner.address] }),
    false,
  );

  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [bob, usd(10)], account: owner }),
    'NotAgent',
  );

  // and back, in one transaction. the cost of revoking a healthy agent is that
  // it stops paying until you undo it, which is what makes it safe to reach for
  // on suspicion rather than on proof.
  await send(guard, GUARD.abi, 'setAgent', [owner.address, true]);
  await send(guard, GUARD.abi, 'guardedPay', [bob, usd(10)]);
});

test('revocation is checked before policy, so it stops payments policy likes', async () => {
  // guardedPay checks isAgent on its first line and only then calls assess, so a
  // revoked agent is refused with NotAgent rather than Denied - no judgement
  // about the recipient is involved or even reached. that is the difference
  // between a kill switch and one more rule: every other rule needs the payment
  // to look wrong, and this one doesn't. bob is still clear here, and the guard
  // says so, and the payment is refused anyway.
  await send(guard, GUARD.abi, 'setAgent', [owner.address, false]);

  const verdict = await assess(bob, 10);
  assert.equal(verdict.verdict, V.PAY);
  assert.equal(verdict.reason, 'clear');

  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [bob, usd(10)], account: owner }),
    'NotAgent',
  );
});

test('setDailyLimit(0) removes the cap, it does not freeze spending', async () => {
  // worth a test because it reads the other way round, and an owner reaching for
  // it mid-incident would be removing the only rate limit in the contract rather
  // than closing it. assess treats 0 as "no cap configured" (`dailyLimit != 0 &&
  // ...`), so this is the off switch, not the stop switch.
  await send(guard, GUARD.abi, 'setDailyLimit', [0n]);
  assert.equal((await assess(bob, 100_000)).verdict, V.PAY); // far past the old 100
  await send(guard, GUARD.abi, 'guardedPay', [bob, usd(1000)]); // and it lands

  // the freeze is one base unit: any payment worth making is then over the cap.
  await send(guard, GUARD.abi, 'setDailyLimit', [1n]);
  const frozen = await assess(bob, 1);
  assert.equal(frozen.verdict, V.REVIEW);
  assert.equal(frozen.reason, 'over daily limit');
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [bob, usd(1)], account: owner }),
    'over daily limit',
  );
});

test('guardedPay: paying the honeypot reverts (unvetted contract)', async () => {
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [honeypot, usd(10)], account: owner }),
    'unvetted contract recipient',
  );
});

test('a blocked codehash overrides the allowlist', async () => {
  // allow the honeypot address, so on its own it would pass...
  await send(guard, GUARD.abi, 'setAllowedContract', [honeypot, true]);
  assert.equal((await assess(honeypot, 10)).verdict, V.PAY);

  // ...then block its whole bytecode family by codehash -> BLOCK wins
  const code = await pub.getCode({ address: honeypot });
  await send(guard, GUARD.abi, 'setBlockedCodehash', [keccak256(code), true]);
  const { verdict, reason } = await assess(honeypot, 10);
  assert.equal(verdict, V.BLOCK);
  assert.equal(reason, 'recipient code is blocklisted');
});

test('recording a malicious contract flips it from REVIEW to BLOCK', async () => {
  // this is what recordVerdictOnChain() does off-chain once the analyzer + llm
  // confirm a honeypot: block the recipient's whole bytecode family by codehash.
  // an unvetted contract starts at REVIEW...
  assert.equal((await assess(honeypot, 10)).verdict, V.REVIEW);

  const code = await pub.getCode({ address: honeypot });
  await send(guard, GUARD.abi, 'setBlockedCodehash', [keccak256(code), true]);

  // ...and after the verdict is written on-chain, the guard blocks it itself.
  const after = await assess(honeypot, 10);
  assert.equal(after.verdict, V.BLOCK);
  assert.equal(after.reason, 'recipient code is blocklisted');
});

test('allowlisting a vetted contract flips it from REVIEW to PAY', async () => {
  // the allow direction of the bridge (allowlistOnChain): once the owner vets a
  // contract, the guard auto-pays it. use the mock token as a stand-in benign
  // contract recipient - it has code, so it starts unvetted at REVIEW...
  assert.equal((await assess(usdc, 10)).verdict, V.REVIEW);

  await send(guard, GUARD.abi, 'setAllowedContract', [usdc, true]);

  // ...and after it's allowlisted the guard is happy to pay it.
  const after = await assess(usdc, 10);
  assert.equal(after.verdict, V.PAY);
  assert.equal(after.reason, 'clear');
});

test('behavior lane: spend past the daily limit is REVIEW', async () => {
  // limit is 100; spend 60 first, then 60 more would cross it
  await send(guard, GUARD.abi, 'guardedPay', [bob, usd(60)]);
  assert.equal((await assess(bob, 60)).verdict, V.REVIEW);
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [bob, usd(60)], account: owner }),
    'over daily limit',
  );
});

test('JIT float: refilling the x402 wallet draws on the same daily limit', async () => {
  // x402 payments settle off-mempool, so the guard can't revert them directly.
  // instead the agent's x402 wallet holds only a float that the treasury tops up
  // THROUGH guardedPay - so its refills draw on the same daily cap. limit is 100:
  // a 70 refill lands, but a second 70 refill would cross the cap and reverts.
  // that is what bounds total x402 spend even though the guard isn't in its path.
  await send(guard, GUARD.abi, 'guardedPay', [floatWallet, usd(70)]);
  const funded = await pub.readContract({
    address: usdc, abi: MOCK.abi, functionName: 'balanceOf', args: [floatWallet],
  });
  assert.equal(funded, usd(70));

  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: [floatWallet, usd(70)], account: owner }),
    'over daily limit',
  );
});

test('only the owner can change policy', async () => {
  // every owner-gated setter, not just one - the name makes a general claim, so
  // the assertions have to cover the whole surface. setTreasury in particular is
  // what the treasury/agent split depends on: if its modifier ever went missing,
  // an outsider could point the guard at a treasury they control.
  const ownerOnly = [
    ['setDenylisted', [bob, true]],
    ['setAgent', [bob, true]],
    ['setAllowedContract', [bob, true]],
    ['setBlockedCodehash', [`0x${'11'.repeat(32)}`, true]],
    ['setDailyLimit', [usd(1)]],
    ['setTreasury', [bob]],
    ['transferOwnership', [bob]],
  ];
  for (const [functionName, args] of ownerOnly) {
    try {
      await expectRevert(
        () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName, args, account: outsider }),
        'NotOwner',
      );
    } catch (err) {
      // name the offender, or a failure here just says "NotOwner expected"
      throw new Error(`${functionName} is not owner-gated: ${err.message}`);
    }
  }
});

test('ownership transfer is two-step: proposing does not hand over control', async () => {
  await send(guard, GUARD.abi, 'transferOwnership', [outsider.address]);

  // still the old owner until the new one accepts, which is the whole point -
  // a wrong address cannot brick admin, because it never becomes admin.
  assert.equal(
    (await pub.readContract({ address: guard, abi: GUARD.abi, functionName: 'owner' })).toLowerCase(),
    owner.address.toLowerCase(),
  );
  assert.equal(
    (await pub.readContract({ address: guard, abi: GUARD.abi, functionName: 'pendingOwner' })).toLowerCase(),
    outsider.address.toLowerCase(),
  );

  // and nobody else can accept on their behalf
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'acceptOwnership', account: owner }),
    'NotOwner',
  );

  await send(guard, GUARD.abi, 'acceptOwnership', [], outsider);
  assert.equal(
    (await pub.readContract({ address: guard, abi: GUARD.abi, functionName: 'owner' })).toLowerCase(),
    outsider.address.toLowerCase(),
  );
});

test('setTreasury repoints where the money is pulled from', async () => {
  // the on-chain half of `npm run rotate-keys`. bob funds and approves, the
  // owner repoints, and the next guardedPay must debit bob, not the old treasury.
  await send(usdc, MOCK.abi, 'mint', [bob, usd(100)]);
  const asBob = createWalletClient({ account: privateKeyToAccount(PK.bob), chain: foundry, transport: http(RPC) });
  const approve = await asBob.writeContract({
    address: usdc, abi: MOCK.abi, functionName: 'approve', args: [guard, usd(100)],
  });
  await pub.waitForTransactionReceipt({ hash: approve });

  await send(guard, GUARD.abi, 'setTreasury', [bob]);
  const before = await pub.readContract({ address: usdc, abi: MOCK.abi, functionName: 'balanceOf', args: [bob] });
  await send(guard, GUARD.abi, 'guardedPay', [floatWallet, usd(5)]);
  const after = await pub.readContract({ address: usdc, abi: MOCK.abi, functionName: 'balanceOf', args: [bob] });

  assert.equal(before - after, usd(5), 'the new treasury should have been debited');
});

test('a payment to the zero address is blocked', async () => {
  const { verdict, reason } = await assess('0x0000000000000000000000000000000000000000', 1);
  assert.equal(verdict, 1); // Block
  assert.equal(reason, 'zero address');
  await expectRevert(
    () => pub.simulateContract({ address: guard, abi: GUARD.abi, functionName: 'guardedPay', args: ['0x0000000000000000000000000000000000000000', usd(1)], account: owner }),
    'zero address',
  );
});

test('every verdict the deployed contract can give maps onto a refusal code', async () => {
  // src/refusals.js translates AegisGuard's prose into the same vocabulary the
  // off-chain rail uses, and test/refusals.test.mjs checks that map against the
  // contract SOURCE. this checks it against the contract as actually compiled
  // and deployed, one policy path at a time, because the source is not what
  // answers an RPC call.
  const ZERO = '0x0000000000000000000000000000000000000000';

  assert.equal(guardReasonCode((await assess(bob, 10)).reason), null); // "clear"
  assert.equal(guardReasonCode((await assess(ZERO, 10)).reason), REFUSAL.ZERO_ADDRESS);
  assert.equal(guardReasonCode((await assess(honeypot, 10)).reason), REFUSAL.UNVETTED_CONTRACT);

  await send(guard, GUARD.abi, 'setDenylisted', [bob, true]);
  assert.equal(guardReasonCode((await assess(bob, 10)).reason), REFUSAL.DENYLISTED);
  await send(guard, GUARD.abi, 'setDenylisted', [bob, false]);

  const code = await pub.getCode({ address: honeypot });
  await send(guard, GUARD.abi, 'setBlockedCodehash', [keccak256(code), true]);
  assert.equal(guardReasonCode((await assess(honeypot, 10)).reason), REFUSAL.BLOCKED_CODEHASH);

  // limit is 100, so 200 is over it
  assert.equal(guardReasonCode((await assess(bob, 200)).reason), REFUSAL.DAILY_CAP);
});

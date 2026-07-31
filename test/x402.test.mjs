// offline tests for the Aegis x402 signer - the EIP-3009 enforcement chokepoint.
// no network: the policy verdict is injected so we exercise the guard itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import { createAegisSigner, AegisPaymentRefused } from '../src/x402/signer.js';
import { DECISION } from '../src/aegis.js';

// a throwaway well-known test key (anvil #0). signing is pure crypto, no chain.
const account = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');

const USDC = '0x3600000000000000000000000000000000000000';
const CHAIN_ID = 5042002;
const NOW = 1000;

const PAYTO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';
const TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
};

// build a TransferWithAuthorization typed-data payload, with knobs to break it.
function payment({ asset = USDC, chainId = CHAIN_ID, to = PAYTO, value = 10_000n, ttl = 60 } = {}) {
  return {
    domain: { name: 'USDC', version: '2', chainId, verifyingContract: asset },
    types: TYPES,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: account.address,
      to,
      value,
      validAfter: 0n,
      validBefore: BigInt(NOW + ttl),
      nonce: '0x' + '11'.repeat(32),
    },
  };
}

// a signer whose policy verdict and clock are fixed, so tests are deterministic.
function signerWith(decision, extra = {}) {
  return createAegisSigner(account, {
    usdc: USDC,
    chainId: CHAIN_ID,
    now: () => NOW,
    balanceOf: async () => 1000000000n, // offline: a wallet with plenty of float
    check: async () => ({ decision, reasons: ['(injected)'] }),
    ...extra,
  });
}

test('signs a clean PAY payment (returns a real signature)', async () => {
  const sig = await signerWith(DECISION.PAY).signTypedData(payment());
  assert.match(sig, /^0x[0-9a-f]{130}$/i); // 65-byte ecdsa signature
});

test('refuses when the verdict is BLOCK', async () => {
  await assert.rejects(
    () => signerWith(DECISION.BLOCK).signTypedData(payment()),
    (e) => e instanceof AegisPaymentRefused && e.verdict === DECISION.BLOCK,
  );
});

test('refuses when the verdict is ASK_HUMAN', async () => {
  await assert.rejects(
    () => signerWith(DECISION.ASK_HUMAN).signTypedData(payment()),
    (e) => e instanceof AegisPaymentRefused && e.verdict === DECISION.ASK_HUMAN,
  );
});

test('refuses to sign for more than the wallet actually holds', async () => {
  // a PAY verdict is not enough. an authorization the float can't cover today
  // still settles the moment someone tops the wallet up, so it must not exist.
  const poor = signerWith(DECISION.PAY, { balanceOf: async () => 9_999n });
  await assert.rejects(
    () => poor.signTypedData(payment({ value: 10_000n })),
    (e) => e instanceof AegisPaymentRefused && /wallet holds/.test(e.reason),
  );
});

test('signs when the balance covers the authorization exactly', async () => {
  // the boundary goes the other way: equal is coverable, so it must sign.
  const exact = signerWith(DECISION.PAY, { balanceOf: async () => 10_000n });
  const sig = await exact.signTypedData(payment({ value: 10_000n }));
  assert.match(sig, /^0x[0-9a-f]{130}$/i);
});

test('refuses a foreign asset even when the verdict would be PAY', async () => {
  // the killer case: a hostile 402 names its own contract "USDC".
  const evilAsset = '0x000000000000000000000000000000000000dEaD';
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(payment({ asset: evilAsset })),
    (e) => e instanceof AegisPaymentRefused && /canonical USDC/.test(e.reason),
  );
});

test('refuses an authorization scoped to another chain', async () => {
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(payment({ chainId: 1 })),
    (e) => e instanceof AegisPaymentRefused && /chainId/.test(e.reason),
  );
});

test('refuses a long-lived authorization (delayed-drain guard)', async () => {
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(payment({ ttl: 3600 })),
    (e) => e instanceof AegisPaymentRefused && /cap/.test(e.reason),
  );
});

test('non-payment typed data passes straight through', async () => {
  // a generic EIP-712 login should not be touched by the payment guard.
  const login = {
    domain: { name: 'Login', version: '1', chainId: CHAIN_ID },
    types: { Login: [{ name: 'user', type: 'address' }] },
    primaryType: 'Login',
    message: { user: account.address },
  };
  // verdict is BLOCK, but this isn't a payment, so it must still sign.
  const sig = await signerWith(DECISION.BLOCK).signTypedData(login);
  assert.match(sig, /^0x[0-9a-f]{130}$/i);
});

test('refuses an EIP-2612 Permit on the guarded USDC (allowance drain)', async () => {
  const permit = {
    domain: { name: 'USDC', version: '2', chainId: CHAIN_ID, verifyingContract: USDC },
    types: {
      Permit: [
        { name: 'owner', type: 'address' }, { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' }, { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'Permit',
    message: {
      owner: account.address,
      spender: '0x000000000000000000000000000000000000dEaD',
      value: 2n ** 256n - 1n, nonce: 0n, deadline: 99999999999n,
    },
  };
  // verdict PAY, but a Permit on our USDC is a fund-moving primitive: refuse.
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(permit),
    (e) => e instanceof AegisPaymentRefused && /disabled/.test(e.reason),
  );
});

test('disables raw signing primitives (sign / signTransaction / signAuthorization)', () => {
  const s = signerWith(DECISION.PAY);
  assert.throws(() => s.sign({ hash: '0x' + '00'.repeat(32) }), AegisPaymentRefused);
  assert.throws(() => s.signTransaction({}), AegisPaymentRefused);
  assert.throws(() => s.signAuthorization({}), AegisPaymentRefused);
});

test('guards ReceiveWithAuthorization as well as Transfer', async () => {
  const recv = {
    ...payment(),
    primaryType: 'ReceiveWithAuthorization',
    types: { ReceiveWithAuthorization: TYPES.TransferWithAuthorization },
  };
  await assert.rejects(
    () => signerWith(DECISION.BLOCK).signTypedData(recv),
    (e) => e instanceof AegisPaymentRefused,
  );
});

test('a malformed value is a refusal, not a raw crash', async () => {
  const base = payment();
  const bad = { ...base, message: { ...base.message, value: 'abc' } };
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(bad),
    (e) => e instanceof AegisPaymentRefused && /malformed/.test(e.reason),
  );
});

test('TTL boundary: exactly the cap signs, one second over refuses', async () => {
  await signerWith(DECISION.PAY).signTypedData(payment({ ttl: 120 })); // == cap, ok
  await assert.rejects(
    () => signerWith(DECISION.PAY).signTypedData(payment({ ttl: 121 })),
    (e) => e instanceof AegisPaymentRefused,
  );
});

// ---- the refusal codes ----
// every refusal this signer raises carries a code beside its prose (see
// src/refusals.js). the codes are what a caller can branch on; the prose is
// still the answer. this walks every path at once, because the failure mode
// worth catching is a new refusal added later with no code on it.
test('every refusal the signer raises names itself with a code', async () => {
  const cases = [
    ['WRONG_ASSET', () => signerWith(DECISION.PAY).signTypedData(payment({ asset: '0x000000000000000000000000000000000000dEaD' }))],
    ['WRONG_CHAIN', () => signerWith(DECISION.PAY).signTypedData(payment({ chainId: 1 }))],
    ['VALIDITY_WINDOW', () => signerWith(DECISION.PAY).signTypedData(payment({ ttl: 60 * 60 }))],
    ['BAD_AMOUNT', () => signerWith(DECISION.PAY).signTypedData(payment({ value: 0n }))],
    ['MALFORMED_AUTHORIZATION', () => {
      const p = payment();
      p.message.value = 'not a number';
      return signerWith(DECISION.PAY).signTypedData(p);
    }],
    ['EXCEEDS_BALANCE', () => signerWith(DECISION.PAY, { balanceOf: async () => 1n }).signTypedData(payment())],
    ['FUND_MOVING_PRIMITIVE', () => {
      const p = payment();
      p.primaryType = 'Permit';
      return signerWith(DECISION.PAY).signTypedData(p);
    }],
    ['DISABLED_PRIMITIVE', async () => signerWith(DECISION.PAY).sign({ hash: '0x' + '00'.repeat(32) })],
  ];

  for (const [code, run] of cases) {
    const err = await Promise.resolve().then(run).then(() => null, (e) => e);
    assert.ok(err instanceof AegisPaymentRefused, `${code}: expected a refusal`);
    assert.equal(err.code, code);
    assert.ok(err.reason.length > 0, `${code}: a code never replaces the prose`);
  }
});

test('a policy refusal carries the lane code, not a generic one', async () => {
  // the difference between "policy said no" and "denylisted". the engine already
  // worked out which lane refused; the signer hands that through rather than
  // flattening every verdict into one code.
  const signer = createAegisSigner(account, {
    usdc: USDC, chainId: CHAIN_ID, now: () => NOW,
    balanceOf: async () => 1000000000n,
    check: async () => ({ decision: DECISION.BLOCK, code: 'DENYLISTED', reasons: ['Reputation: known bad'] }),
  });
  const err = await signer.signTypedData(payment()).then(() => null, (e) => e);
  assert.ok(err instanceof AegisPaymentRefused);
  assert.equal(err.code, 'DENYLISTED');
  assert.equal(err.verdict, DECISION.BLOCK);
});

test('a verdict with no code of its own becomes UNKNOWN, not null', async () => {
  // an engine that refused without saying which lane did it is a gap worth
  // seeing in the output, so it gets the honest word rather than an empty field.
  const err = await signerWith(DECISION.BLOCK).signTypedData(payment()).then(() => null, (e) => e);
  assert.ok(err instanceof AegisPaymentRefused);
  assert.equal(err.code, 'UNKNOWN');
});

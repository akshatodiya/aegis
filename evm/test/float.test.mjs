// offline tests for the JIT-float top-up decision (floatPlan). the branch logic
// - when to refill, and by how much - is pure and chain-free; the on-chain half
// (ensureFloat actually calling guardedPay, metered by the daily cap) is covered
// against anvil in guard.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseUnits } from 'viem';
import { floatPlan, gasFloatPlan } from '../src/guard.js';

const usd = (n) => parseUnits(String(n), 6); // 6-dec base units, same as the guard
const gas = (n) => parseUnits(String(n), 18); // native USDC on Arc is 18-dec

test('no top-up while the float is at or above the refill threshold', () => {
  assert.deepEqual(floatPlan({ balance: usd(5), target: usd(5), min: usd(2) }), { topUp: false, amount: 0n });
  // exactly at min still counts as enough - don't churn a guard tx on the boundary
  assert.deepEqual(floatPlan({ balance: usd(2), target: usd(5), min: usd(2) }), { topUp: false, amount: 0n });
});

test('tops back up to target (not just to min) once below the threshold', () => {
  const plan = floatPlan({ balance: usd(1), target: usd(5), min: usd(2) });
  assert.equal(plan.topUp, true);
  assert.equal(plan.amount, usd(4)); // 5 - 1, refill to the full target
});

test('an empty float asks for the whole target', () => {
  assert.deepEqual(floatPlan({ balance: 0n, target: usd(5), min: usd(2) }), { topUp: true, amount: usd(5) });
});

test('min defaulting to target refills on any shortfall', () => {
  // callers can pass min == target; then any dip below target triggers a refill
  assert.deepEqual(floatPlan({ balance: usd(3), target: usd(5), min: usd(5) }), { topUp: true, amount: usd(2) });
});

test('a min above target is a misconfiguration, not a silent pass', () => {
  assert.throws(() => floatPlan({ balance: 0n, target: usd(2), min: usd(5) }), /cannot exceed target/);
});

// --- the agent's gas float ---
// same refill logic, 18-dec native units, plus the direction the x402 float
// doesn't need: on Arc gas is USDC, so an over-funded agent wallet is burnable
// money the guard has no way to reach.

test('the gas float refills on the same rules as the x402 float', () => {
  assert.deepEqual(gasFloatPlan({ balance: gas(0.05), target: gas(0.05), min: gas(0.02) }), { topUp: false, amount: 0n, exposure: 0n });
  const plan = gasFloatPlan({ balance: gas(0.01), target: gas(0.05), min: gas(0.02) });
  assert.equal(plan.topUp, true);
  assert.equal(plan.amount, gas(0.04)); // back up to target, not just to min
});

test('a gas balance above the float is reported as exposure, not as fine', () => {
  // the whole point: surplus gas money is what a hijacked key gets to burn,
  // and no on-chain rule can stop it - so it has to be visible.
  const plan = gasFloatPlan({ balance: gas(5), target: gas(0.05), min: gas(0.02) });
  assert.equal(plan.topUp, false);
  assert.equal(plan.exposure, gas(4.95));
});

test('a gas float at target exactly is neither a refill nor exposure', () => {
  const plan = gasFloatPlan({ balance: gas(0.05), target: gas(0.05), min: gas(0.05) });
  assert.deepEqual(plan, { topUp: false, amount: 0n, exposure: 0n });
});

test('a gas min above target is a misconfiguration too', () => {
  assert.throws(() => gasFloatPlan({ balance: 0n, target: gas(1), min: gas(2) }), /cannot exceed target/);
});

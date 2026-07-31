// tests for the refusal codes - the machine-readable half of every refusal.
//
// Codes are cheap to add and expensive to be wrong about, because the whole
// point of one is that something downstream can branch on it. Three failure
// modes are worth pinning: a code that stops being raised anywhere and quietly
// becomes a word in a list, a code that drifts away from the contract string it
// claims to translate, and a code that gets read back out of a string that never
// carried one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  REFUSAL, REFUSAL_CODES, isRefusalCode,
  guardReasonCode, guardErrorCode, stampReason, readStamp,
} from '../src/refusals.js';

const ROOT = new URL('..', import.meta.url).pathname;

function sourceFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sourceFiles(path, out);
    else if (name.endsWith('.js')) out.push(path);
  }
  return out;
}

test('the vocabulary is a frozen set of keys that equal their values', () => {
  // a typo in REFUSAL.SOMETHING is `undefined`, and undefined would sail through
  // any code path that just passes it along. keys matching values means a stray
  // string literal and the constant are interchangeable, so the constant is the
  // only thing anyone has to remember.
  assert.ok(Object.isFrozen(REFUSAL));
  for (const [key, value] of Object.entries(REFUSAL)) assert.equal(key, value);
  assert.equal(REFUSAL_CODES.length, Object.keys(REFUSAL).length);
  assert.ok(isRefusalCode(REFUSAL.DENYLISTED));
  assert.ok(!isRefusalCode('denylisted'), 'codes are exact, not case-insensitive');
  assert.ok(!isRefusalCode('MADE_UP'));
  assert.ok(!isRefusalCode(null));
});

test('every code is actually raised somewhere', () => {
  // a vocabulary that accumulates dead words is worse than no vocabulary: it
  // makes the list look like it describes the system when it describes history.
  // each code is defined once in refusals.js, so anything appearing only once
  // across the whole source tree is defined and never used.
  const files = [...sourceFiles(join(ROOT, 'src')), ...sourceFiles(join(ROOT, 'scripts'))];
  const source = files.map((f) => readFileSync(f, 'utf8')).join('\n');

  for (const code of REFUSAL_CODES) {
    const uses = source.match(new RegExp(`\\b${code}\\b`, 'g')) ?? [];
    assert.ok(uses.length >= 2, `${code} is defined but never raised (${uses.length} occurrence)`);
  }
});

test('the guard reason map matches what the contract actually says', () => {
  // AegisGuard is deployed and verified, so its strings can never be edited to
  // match this map - the map has to match them. reading the source rather than
  // trusting the map means a new assess() branch fails here instead of silently
  // becoming UNKNOWN in production.
  const sol = readFileSync(join(ROOT, 'contracts', 'AegisGuard.sol'), 'utf8');
  const returns = [...sol.matchAll(/return\s*\(\s*Verdict\.(\w+)\s*,\s*"([^"]+)"\s*\)/g)];
  assert.ok(returns.length >= 6, `expected assess() to have several branches, found ${returns.length}`);

  for (const [, verdict, reason] of returns) {
    const code = guardReasonCode(reason);
    if (verdict === 'Pay') {
      assert.equal(code, null, `a Pay verdict ("${reason}") is not a refusal and needs no code`);
    } else {
      assert.ok(code && code !== REFUSAL.UNKNOWN, `the contract can say "${reason}" and nothing maps it`);
    }
  }
});

test('an unrecognized on-chain reason is UNKNOWN, never a near-match', () => {
  assert.equal(guardReasonCode('recipient denylisted'), REFUSAL.DENYLISTED);
  assert.equal(guardReasonCode('  Recipient Denylisted  '), REFUSAL.DENYLISTED, 'trimmed and case-folded');
  assert.equal(guardReasonCode('clear'), null);
  // close to "over daily limit" but not it. guessing here would let a future
  // contract mean something new while looking like something old.
  assert.equal(guardReasonCode('over the daily limit'), REFUSAL.UNKNOWN);
  assert.equal(guardReasonCode(''), REFUSAL.UNKNOWN);
  assert.equal(guardReasonCode(undefined), REFUSAL.UNKNOWN);
  assert.equal(guardReasonCode(42), REFUSAL.UNKNOWN);
});

test('the guard custom errors map onto the same vocabulary', () => {
  assert.equal(guardErrorCode('NotAgent'), REFUSAL.NOT_AN_AGENT);
  assert.equal(guardErrorCode('TransferFailed'), REFUSAL.TRANSFER_FAILED);
  // Denied carries a reason string of its own, so it is read by guardReasonCode
  // and deliberately has no entry here.
  assert.equal(guardErrorCode('Denied'), null);
  assert.equal(guardErrorCode('SomethingNew'), null);
});

test('every custom error the contract declares is either mapped or deliberately not', () => {
  const sol = readFileSync(join(ROOT, 'contracts', 'AegisGuard.sol'), 'utf8');
  const declared = [...sol.matchAll(/^\s*error\s+(\w+)\s*\(/gm)].map((m) => m[1]);
  assert.ok(declared.includes('NotAgent'), 'sanity: the parse found the error list');

  // NotOwner is an owner-only setter guard, not a refusal of a payment, and
  // Denied is read from its reason string. everything else has to be mapped.
  const notPaymentRefusals = new Set(['NotOwner', 'Denied']);
  for (const name of declared) {
    if (notPaymentRefusals.has(name)) continue;
    assert.ok(guardErrorCode(name), `${name} can revert a payment and has no code`);
  }
});

test('a code rides at the front of a reason, and comes back off it', () => {
  const stamped = stampReason(REFUSAL.DAILY_CAP, 'over daily limit');
  assert.equal(stamped, 'DAILY_CAP: over daily limit');
  assert.deepEqual(readStamp(stamped), { code: REFUSAL.DAILY_CAP, reason: 'over daily limit' });
});

test('a reason with no code is left exactly as it was', () => {
  // which is what every entry already written to AegisAuditLog looks like, and
  // they have to keep reading correctly forever.
  assert.equal(stampReason(null, 'bait-and-switch: over its posted price'), 'bait-and-switch: over its posted price');
  assert.deepEqual(
    readStamp('bait-and-switch: "Forecast API" is demanding 5000000 base units'),
    { code: null, reason: 'bait-and-switch: "Forecast API" is demanding 5000000 base units' },
  );
});

test('only codes this file defines are read back as codes', () => {
  // a reason is allowed to begin with something shaped like a code. treating
  // that as one would let a counterparty label our own audit entry.
  assert.deepEqual(readStamp('URGENT: pay this now'), { code: null, reason: 'URGENT: pay this now' });
  assert.deepEqual(readStamp('APPROVED: by your owner'), { code: null, reason: 'APPROVED: by your owner' });
});

test('a code with nothing to say is still a code, and a bad code says so', () => {
  assert.equal(stampReason(REFUSAL.NO_APPROVER, ''), 'NO_APPROVER');
  assert.deepEqual(readStamp('NO_APPROVER'), { code: REFUSAL.NO_APPROVER, reason: '' });
  // a caller that passes something that isn't a code meant to say SOMETHING, so
  // this records that it couldn't be understood rather than dropping it.
  assert.equal(stampReason('DENYLISTD', 'typo above'), 'UNKNOWN: typo above');
  assert.equal(stampReason(undefined, 'nothing to add'), 'nothing to add');
});

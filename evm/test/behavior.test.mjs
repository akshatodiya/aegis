// offline tests for the behavior lane's decision. the log query that produces
// the payment history is chain-side; the branch logic is pure and lives here.
//
// the distinction these are really guarding: "we have never paid them",
// "we have paid them before" and "we could not find out" are three different
// answers, and the lane used to collapse all of them into the first one.
//
// and the one below that: "paid before" is a claim about size as well as count.
// counting alone is a signal an attacker can buy for a dollar, so the farming
// case has its own tests rather than being left to the reader.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { behaviorVerdict } from '../src/lanes/behavior.js';

const NEVER = { count: 0, largest: 0 };
const UNKNOWN = null;
const paid = (count, largest) => ({ count, largest });

test('a large payment to an unseen recipient escalates', () => {
  const v = behaviorVerdict(60, NEVER);
  assert.equal(v.level, 'MEDIUM');
  assert.equal(v.escalate, true);
  assert.match(v.reason, /not paid in its recent history/);
});

test('a large payment in line with what we have paid before does not escalate', () => {
  const v = behaviorVerdict(60, paid(3, 200));
  assert.equal(v.level, 'LOW');
  assert.equal(v.escalate, false);
  assert.match(v.reason, /paid 3 times before, up to 200 USDC/);
});

test('an unreadable history escalates a large payment, and says so honestly', () => {
  // this must NOT be reported as "never paid them" - we do not know that.
  const v = behaviorVerdict(60, UNKNOWN);
  assert.equal(v.escalate, true);
  assert.match(v.reason, /could not be read/);
  assert.doesNotMatch(v.reason, /never/);
});

test('a small payment stays LOW whatever the history says', () => {
  for (const history of [NEVER, paid(1, 1), UNKNOWN]) {
    const v = behaviorVerdict(5, history);
    assert.equal(v.level, 'LOW');
    assert.equal(v.escalate, false);
  }
});

test('the threshold is exclusive - exactly at the limit is not large', () => {
  assert.equal(behaviorVerdict(50, NEVER).escalate, false);
  assert.equal(behaviorVerdict(51, NEVER).escalate, true);
});

test('singular and plural read correctly', () => {
  assert.match(behaviorVerdict(5, paid(1, 1)).reason, /paid 1 time before/);
  assert.match(behaviorVerdict(5, paid(2, 1)).reason, /paid 2 times before/);
});

// the farming case. one dust payment used to buy a permanent pass at any size,
// because the lane asked whether the count was zero and nothing else.
test('a dust payment does not launder a huge one to the same address', () => {
  const dust = behaviorVerdict(1, NEVER);
  assert.equal(dust.escalate, false, 'the small payment itself still passes - that is what makes it cheap');

  const v = behaviorVerdict(500, paid(1, 1));
  assert.equal(v.escalate, true, 'a 500 USDC payment must not ride on a 1 USDC history');
  assert.match(v.reason, /largest the guard has paid this recipient before \(1 USDC/);
});

test('familiarity is capped at a multiple of what we actually paid them', () => {
  // 5x the largest prior payment is the line, and it is exclusive.
  assert.equal(behaviorVerdict(500, paid(2, 100)).escalate, false, 'exactly 5x still passes');
  assert.equal(behaviorVerdict(501, paid(2, 100)).escalate, true, 'one over 5x escalates');
});

test('a genuine relationship is not punished for growing', () => {
  // the point is to stop dust laundering a whale, not to freeze a real payee at
  // its first invoice. paying somewhat more than last time stays quiet.
  assert.equal(behaviorVerdict(300, paid(4, 250)).escalate, false);
  assert.equal(behaviorVerdict(900, paid(9, 800)).escalate, false);
});

test('a big history does not excuse an unrelated jump', () => {
  // many small payments are still many small payments.
  assert.equal(behaviorVerdict(10_000, paid(40, 20)).escalate, true);
});

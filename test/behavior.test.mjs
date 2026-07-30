// offline tests for the behavior lane's decision. the log query that produces
// the payment count is chain-side; the branch logic is pure and lives here.
//
// the distinction these are really guarding: "we have never paid them",
// "we have paid them before" and "we could not find out" are three different
// answers, and the lane used to collapse all of them into the first one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { behaviorVerdict } from '../src/lanes/behavior.js';

const NEVER = 0;
const UNKNOWN = null;

test('a large payment to an unseen recipient escalates', () => {
  const v = behaviorVerdict(60, NEVER);
  assert.equal(v.level, 'MEDIUM');
  assert.equal(v.escalate, true);
  assert.match(v.reason, /not paid in its recent history/);
});

test('a large payment to a recipient we have paid before does not escalate', () => {
  const v = behaviorVerdict(60, 3);
  assert.equal(v.level, 'LOW');
  assert.equal(v.escalate, false);
  assert.match(v.reason, /paid 3 times before/);
});

test('an unreadable history escalates a large payment, and says so honestly', () => {
  // this must NOT be reported as "never paid them" - we do not know that.
  const v = behaviorVerdict(60, UNKNOWN);
  assert.equal(v.escalate, true);
  assert.match(v.reason, /could not be read/);
  assert.doesNotMatch(v.reason, /never/);
});

test('a small payment stays LOW whatever the history says', () => {
  for (const paid of [NEVER, 1, UNKNOWN]) {
    const v = behaviorVerdict(5, paid);
    assert.equal(v.level, 'LOW');
    assert.equal(v.escalate, false);
  }
});

test('the threshold is exclusive - exactly at the limit is not large', () => {
  assert.equal(behaviorVerdict(50, NEVER).escalate, false);
  assert.equal(behaviorVerdict(51, NEVER).escalate, true);
});

test('singular and plural read correctly', () => {
  assert.match(behaviorVerdict(5, 1).reason, /paid 1 time before/);
  assert.match(behaviorVerdict(5, 2).reason, /paid 2 times before/);
});

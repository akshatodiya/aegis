// offline tests for the audit logger - the piece that turns an x402 refusal into
// an on-chain receipt. no anvil, no network: the write is injected, so what's
// under test is the part that runs on the failure path.
//
// that's the part worth pinning. this code only ever executes when something has
// already gone wrong, which means every value reaching it is a value that was
// wrong enough to get a payment refused: an address that isn't one, an amount a
// hostile server chose, a reason string quoting both. and it has to do all that
// without throwing, because the one thing worse than a missing receipt is a
// firewall that crashes while refusing.
import { test } from 'node:test';
import assert from 'node:assert/strict';

// config.js binds env at import time, and a real .env with AEGIS_AUDIT_LOG set
// would quietly enable the "no address" case below. dotenv never overwrites an
// existing value, so claiming these first wins.
process.env.CHAIN = 'arc';
process.env.AEGIS_AUDIT_LOG = '';
const { trimReason, refusalEntry, createAuditLogger, AUDIT_VERDICT, MAX_REASON_BYTES } =
  await import('../src/audit.js');
const { AegisPaymentRefused } = await import('../src/x402/signer.js');
const { DECISION } = await import('../src/aegis.js');

const MERCHANT = '0x0000000000000000000000000000000000000011';
const ZERO = '0x0000000000000000000000000000000000000000';
const HASH = `0x${'ab'.repeat(32)}`;
const bytes = (s) => Buffer.byteLength(s, 'utf8');

test('a short reason goes on-chain unchanged', () => {
  assert.equal(trimReason('recipient denylisted'), 'recipient denylisted');
});

test('whitespace is collapsed and an empty reason still says something', () => {
  assert.equal(trimReason('  two\n  lines  '), 'two lines');
  assert.equal(trimReason(''), 'refused (no reason recorded)');
  assert.equal(trimReason(null), 'refused (no reason recorded)');
});

test('an oversized reason is cut to the contract\'s byte limit', () => {
  // the real shape of this: a 402 names its price, the price only had to be
  // digits to get here, and the reason quotes it back. so the merchant picks the
  // length unless we do. over the limit the contract reverts and the receipt is
  // lost - the one failure this whole module exists to avoid.
  const hostile = `bait-and-switch: demanding ${'9'.repeat(5000)} base units`;
  const trimmed = trimReason(hostile);
  assert.ok(bytes(trimmed) <= MAX_REASON_BYTES, `${bytes(trimmed)} bytes is over the limit`);
  assert.ok(trimmed.endsWith('...'), 'a cut reason should say it was cut');
  assert.ok(trimmed.startsWith('bait-and-switch: demanding 99'));
});

test('a cut lands on a character boundary, not inside one', () => {
  // service names come off the wire too, so a reason can be full of multi-byte
  // characters. slicing bytes blindly leaves a half character, which decodes to
  // U+FFFD - three more bytes than we budgeted, which would put us back over the
  // limit we just trimmed to.
  const trimmed = trimReason('ee' + '€'.repeat(300)); // euro sign, 3 bytes each
  assert.ok(bytes(trimmed) <= MAX_REASON_BYTES);
  assert.ok(!trimmed.includes('\uFFFD'), 'a broken character survived the trim');
});

test('an entry carries who, how much, and which verdict', () => {
  const err = new AegisPaymentRefused('recipient denylisted', DECISION.BLOCK, {
    recipient: MERCHANT, amount: 250_000n,
  });
  assert.deepEqual(refusalEntry(err), {
    recipient: MERCHANT,
    amount: 250_000n,
    verdict: AUDIT_VERDICT.BLOCK,
    reason: 'recipient denylisted',
  });
});

test('a refusal that never named a recipient logs the zero address', () => {
  // "no acceptable payment option" is refused before anyone is named. zero says
  // we never got that far; inventing an address would make the log say something
  // that did not happen.
  const err = new AegisPaymentRefused('no acceptable payment option.');
  assert.equal(refusalEntry(err).recipient, ZERO);
  assert.equal(refusalEntry({ reason: 'x', recipient: 'not-an-address' }).recipient, ZERO);
});

test('an amount no uint256 can hold is recorded as zero, not clamped', () => {
  // clamping would put a number in the log that nobody demanded. the reason
  // string still carries what was actually asked for.
  assert.equal(refusalEntry({ reason: 'x', amount: 2n ** 300n }).amount, 0n);
  assert.equal(refusalEntry({ reason: 'x', amount: -5n }).amount, 0n);
  assert.equal(refusalEntry({ reason: 'x', amount: 'twelve' }).amount, 0n);
  assert.equal(refusalEntry({ reason: 'x' }).amount, 0n);
});

test('ASK_HUMAN is the only verdict that is not BLOCK', () => {
  assert.equal(refusalEntry({ reason: 'x', verdict: DECISION.ASK_HUMAN }).verdict, AUDIT_VERDICT.ASK_HUMAN);
  assert.equal(refusalEntry({ reason: 'x', verdict: DECISION.BLOCK }).verdict, AUDIT_VERDICT.BLOCK);
  assert.equal(refusalEntry({ reason: 'x' }).verdict, AUDIT_VERDICT.BLOCK);
});

test('with no contract address the logger is off and onRefuse does nothing', async () => {
  const audit = createAuditLogger();
  assert.equal(audit.enabled, false);
  audit.onRefuse(new AegisPaymentRefused('denylisted', DECISION.BLOCK, { recipient: MERCHANT }));
  const { entries, logged } = await audit.flush();
  assert.equal(entries.length, 0);
  assert.equal(logged, 0);
});

test('one refusal through both hooks is one entry', async () => {
  // the signer refuses and the fetch wrapper re-throws, so the same error object
  // reaches onRefuse twice. two receipts for one refusal would overstate what
  // happened, in a log whose whole value is that it does not.
  const audit = createAuditLogger({ send: async () => HASH });
  const err = new AegisPaymentRefused('verdict BLOCK on payTo', DECISION.BLOCK, { recipient: MERCHANT });
  audit.onRefuse(err); // the signer's hook
  audit.onRefuse(err); // and the fetch wrapper's, on the way out
  const { entries, logged } = await audit.flush();
  assert.equal(entries.length, 1);
  assert.equal(logged, 1);
  assert.equal(entries[0].hash, HASH);
  assert.ok(entries[0].url.includes(HASH));
});

test('two refusals that read the same are still two entries', async () => {
  // dedupe is on the error's identity, not its text. two payments refused for
  // the same reason are two refusals.
  const audit = createAuditLogger({ send: async () => HASH });
  const reason = 'payTo is not a service in the catalog';
  audit.onRefuse(new AegisPaymentRefused(reason, DECISION.BLOCK, { recipient: MERCHANT }));
  audit.onRefuse(new AegisPaymentRefused(reason, DECISION.BLOCK, { recipient: MERCHANT }));
  assert.equal((await audit.flush()).entries.length, 2);
});

test('onRefuse returns without waiting for the transaction', async () => {
  // the refusal already happened. a firewall that waits on its own bookkeeping
  // before it can finish refusing has invented a new way to fail.
  let release;
  const held = new Promise((r) => { release = r; });
  const audit = createAuditLogger({ send: async () => { await held; return HASH; } });

  audit.onRefuse(new AegisPaymentRefused('denylisted', DECISION.BLOCK, { recipient: MERCHANT }));
  assert.equal(audit.entries.length, 1, 'the entry should exist immediately');
  assert.equal(audit.entries[0].hash, undefined, 'and the write should still be in flight');

  release();
  await audit.flush();
  assert.equal(audit.entries[0].hash, HASH);
});

test('a write that fails is recorded, never thrown', async () => {
  // no node, no gas, not a reporter - all real. none of them may turn a refused
  // payment into a crashed agent, and none may surface as an unhandled rejection
  // either, which is why the catch lives inside the logger.
  const audit = createAuditLogger({
    send: async () => { throw new Error('execution reverted: NotReporter'); },
  });
  audit.onRefuse(new AegisPaymentRefused('denylisted', DECISION.BLOCK, { recipient: MERCHANT }));

  const { entries, logged, failed } = await audit.flush();
  assert.equal(logged, 0);
  assert.equal(failed, 1);
  assert.match(entries[0].error, /NotReporter/);
});

test('receipts stop at the cap, refusals do not', async () => {
  // the one way this log can cost something the attacker picks: gas on Arc is
  // USDC, so an agent aimed at a hostile service in a loop would pay for a
  // receipt per refusal. past the cap the refusals still land in `entries` and
  // still print - they just stop being paid for, and flush() says how many.
  const audit = createAuditLogger({ send: async () => HASH, maxWrites: 2 });
  for (const reason of ['one', 'two', 'three', 'four']) {
    audit.onRefuse(new AegisPaymentRefused(reason, DECISION.BLOCK, { recipient: MERCHANT }));
  }

  const { entries, logged, skipped } = await audit.flush();
  assert.equal(entries.length, 4, 'every refusal is still recorded in memory');
  assert.equal(logged, 2);
  assert.equal(skipped, 2);
  assert.deepEqual(entries.map((e) => Boolean(e.skipped)), [false, false, true, true]);
});

test('writes go out one at a time, in order', async () => {
  // they all come from the same key, so two in flight is a nonce collision and
  // one of the receipts is lost.
  const order = [];
  let inFlight = 0;
  const audit = createAuditLogger({
    send: async (entry) => {
      inFlight += 1;
      assert.equal(inFlight, 1, 'two audit writes were in flight at once');
      await new Promise((r) => setTimeout(r, 5));
      order.push(entry.reason);
      inFlight -= 1;
      return HASH;
    },
  });

  for (const reason of ['first', 'second', 'third']) {
    audit.onRefuse(new AegisPaymentRefused(reason, DECISION.BLOCK, { recipient: MERCHANT }));
  }
  await audit.flush();
  assert.deepEqual(order, ['first', 'second', 'third']);
});

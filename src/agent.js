// demo entrypoint. the "agent" is just a script that wants to move money, but
// runs it past aegis first and only goes through if the verdict is PAY.
//
//   node src/agent.js good                    pay recipient A (GOOD_RECIPIENT)
//   node src/agent.js bad                     pay recipient B (BAD_RECIPIENT)
//   node src/agent.js <0xaddr> [amt]          pay any address
//   node src/agent.js approve <good|bad|0x>   approve a spender to move our USDC
//   node src/agent.js guard <good|bad|0x>     pay THROUGH the on-chain AegisGuard
//
// the approve path matters: agents usually lose funds not by sending to a trap
// but by approving a malicious spender that drains them later. so we check the
// spender's code the same way we'd check a recipient.
//
// the guard path routes the payment through the deployed AegisGuard contract,
// so the same policy is enforced on-chain and can't be skipped by the agent.
import { aegisCheck, printVerdict, DECISION } from './aegis.js';
import { payUSDC } from './pay.js';
import { approveUSDC } from './approve.js';
import { createInterface } from 'node:readline/promises';
import { guardedPay, assessOnChain, recordVerdictOnChain, allowlistOnChain, needsVetting, formatAssessment } from './guard.js';
import { addresses, assertAddress } from './config.js';

const DEFAULT_AMOUNT = 10;
const MODES = new Set(['approve', 'guard']);

function resolveTarget(arg) {
  if (arg === 'good') return { recipient: assertAddress('GOOD_RECIPIENT', addresses.good), label: 'Recipient A (good EOA)' };
  if (arg === 'bad') return { recipient: assertAddress('BAD_RECIPIENT', addresses.bad), label: 'Recipient B (malicious contract)' };
  return { recipient: assertAddress('recipient', arg), label: 'custom address' };
}

async function main() {
  const args = process.argv.slice(2);
  const mode = MODES.has(args[0]) ? args[0] : 'pay';
  const isApprove = mode === 'approve';
  const isGuard = mode === 'guard';
  const [targetArg, amountArg] = mode === 'pay' ? args : args.slice(1);

  if (!targetArg) {
    console.log('usage: node src/agent.js [approve|guard] <good|bad|0xADDRESS> [amount]');
    process.exit(1);
  }

  // in approve mode the target is the spender we'd hand an allowance to
  const { recipient, label } = resolveTarget(targetArg);
  const amount = amountArg ? Number(amountArg) : DEFAULT_AMOUNT;
  if (!Number.isFinite(amount) || amount <= 0) {
    console.log(`bad amount: ${amountArg} (must be a positive number)`);
    process.exit(1);
  }

  const intent = isApprove
    ? `approve ${label} to spend ${amount} USDC`
    : isGuard
      ? `pay ${amount} USDC to ${label} through AegisGuard`
      : `pay ${amount} USDC to ${label}`;
  console.log(`\nAgent wants to ${intent}`);
  console.log(`   ${recipient}`);
  console.log('   ...asking Aegis first.');

  // same risk check either way - who are we trusting with our money?
  const result = await aegisCheck(recipient, amount, { isApprove });
  printVerdict(result);

  // guard mode has its own flow: it routes the decision through the deployed
  // AegisGuard, and teaches the guard when the recipient is bad (see runGuard).
  if (isGuard) {
    await runGuard(recipient, amount, result);
    return;
  }

  if (result.decision === DECISION.PAY) {
    if (isApprove) {
      console.log('Aegis cleared it, sending the approval.\n');
      await approveUSDC(recipient, amount);
    } else {
      console.log('Aegis said PAY, firing the transaction.\n');
      await payUSDC(recipient, amount);
    }
  } else if (result.decision === DECISION.BLOCK) {
    const what = isApprove ? 'approval' : 'transaction';
    console.log(`Aegis said BLOCK. ${what} NOT sent, money saved.\n`);
  } else {
    console.log('Aegis said ASK_HUMAN, pausing for human approval (not auto-sent).\n');
  }
}

// guard mode. show the contract's own verdict too, then act on the off-chain
// decision through the on-chain guard:
//   PAY       -> settle the payment via guardedPay (a real transfer).
//   BLOCK     -> record the recipient into the guard's on-chain lists, so the
//                contract will block it by itself from now on, and watch the
//                on-chain verdict flip. no payment is sent.
//   ASK_HUMAN -> stop and leave it for a person.
async function runGuard(recipient, amount, result) {
  const before = await assessOnChain(recipient, amount);
  console.log(`  On-chain AegisGuard.assess(): ${formatAssessment(before)}`);

  if (result.decision === DECISION.PAY) {
    // the guard is stricter than we are: it won't auto-pay a contract it hasn't
    // been told to trust, so a first-time contract recipient reads as REVIEW here
    // even though we judged it safe. offer to vet it - but allowlisting GRANTS
    // trust (a wrong allow lets money out), so we never do it silently: the owner
    // has to say yes once. after that the contract is on the allowlist for good.
    if (before.verdict === 'REVIEW' && (await needsVetting(recipient))) {
      const paid = await vetThenPay(recipient, amount);
      if (!paid) return;
    } else if (before.verdict === 'PAY') {
      console.log('\nAegis said PAY, routing the payment through the guard.\n');
      await guardedPay(recipient, amount);
    } else {
      // on-chain is stricter for some other reason (over the daily limit,
      // denylisted, ...). don't fire a transaction we know would just revert.
      console.log(`\nOn-chain guard says ${formatAssessment(before)}, not sending.\n`);
    }
    return;
  }

  if (result.decision === DECISION.BLOCK) {
    console.log('\nAegis said BLOCK. teaching the guard so it enforces this on-chain too...');
    const rec = await recordVerdictOnChain(recipient);
    console.log(`  ${rec.message}`);
    if (rec.changed) {
      const after = await assessOnChain(recipient, amount);
      console.log(`  On-chain AegisGuard.assess() now: ${formatAssessment(after)}`);
    }
    console.log('\ntransaction NOT sent, money saved - and the guard now blocks it on its own.\n');
    return;
  }

  console.log('\nAegis said ASK_HUMAN, pausing for a human (not auto-sent).\n');
}

// a first-time contract recipient we judged safe: ask the owner to vet it, and
// only if they agree do we allowlist it and pay. returns true if the payment went
// out, false if we stopped (owner declined, or it still isn't PAY on-chain).
async function vetThenPay(recipient, amount) {
  console.log('\nThe guard has never seen this contract, so on-chain it is REVIEW.');
  console.log('Aegis judged it safe off-chain, but allowlisting grants trust - only the owner can.');

  const ok = await confirmOwner(`Allowlist ${recipient} on-chain and pay it ${amount} USDC?`);
  if (!ok) {
    console.log('\nleaving it at REVIEW, no payment sent.\n');
    return false;
  }

  const vetted = await allowlistOnChain(recipient);
  console.log(`  ${vetted.message}`);

  const after = await assessOnChain(recipient, amount);
  console.log(`  On-chain AegisGuard.assess() now: ${formatAssessment(after)}`);
  if (after.verdict !== 'PAY') {
    console.log('\nstill not PAY on-chain, not sending.\n');
    return false;
  }

  console.log('\nallowlisted, routing the payment through the guard.\n');
  await guardedPay(recipient, amount);
  return true;
}

// ask the person at the keyboard a yes/no question. if nobody's there (no TTY -
// piped, CI, a script), default to NO: we never grant trust without a real human.
async function confirmOwner(question) {
  if (!process.stdin.isTTY) {
    console.log(`  (${question} - no interactive owner present, defaulting to no.)`);
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} (y/N) `)).trim().toLowerCase();
    return answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

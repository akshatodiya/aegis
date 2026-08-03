// the kill switch: what you actually do when you think the agent is compromised.
//
//   npm run kill-switch              revoke, show the same payment failing, restore
//   npm run kill-switch -- --stay    revoke and leave it revoked (the real thing)
//   npm run kill-switch -- --restore re-authorize an agent you revoked earlier
//   npm run kill-switch 0xAgent      act on a specific agent instead of this wallet
//
// Every other demo here answers "what stops a bad payment". This one answers the
// question that comes next, which is the one an operator actually asks at 3am:
// the agent is behaving oddly and you do not yet know why - what do you do, and
// how long does it take?
//
// The answer is one owner transaction. setAgent(agent, false) is the first line
// of guardedPay:
//
//     if (!isAgent[msg.sender]) revert NotAgent();
//     (Verdict verdict, string memory reason) = assess(to, amount);
//
// so revocation is checked BEFORE policy is evaluated at all. That ordering is
// the whole point. Every other rule in the guard is a judgement about the
// recipient - denylisted, unvetted, over the cap - and each one needs the
// recipient to look wrong. Revocation needs nothing to look wrong. It stops the
// payments that policy likes, from a recipient the guard still calls clear,
// which is exactly the case you are in when you suspect the agent rather than
// the counterparty.
//
// What it costs to be wrong is worth saying too: revoking a healthy agent
// refuses payments until you put it back, and putting it back is one more
// transaction. That asymmetry is why this is safe to reach for on suspicion.
import { parseUnits, formatUnits, ContractFunctionRevertedError } from 'viem';
import { publicClient, requireWallet, addresses, assertAddress, txUrl } from '../src/config.js';
import { compileGuard } from '../src/compile.js';
import { usdcBalanceOf, formatAssessment } from '../src/guard.js';
import { guardReasonCode, guardErrorCode } from '../src/refusals.js';

// the payment used to show the difference. small on purpose: this beat never
// intends to move money, it intends to show the same call succeeding and then
// not succeeding, so 1 USDC only has to be under the daily cap and covered by
// the treasury's allowance.
const AMOUNT = 1;

const fmt = (baseUnits) => formatUnits(baseUnits, 6);

function beat(label, title) {
  console.log('\n==============================================');
  console.log(`  BEAT ${label}: ${title}`);
  console.log('==============================================');
}

// same shape the rest of the project prints an on-chain verdict in: the verdict,
// its refusal code, and the contract's own words.
function assessment(verdict, reason) {
  return formatAssessment({
    verdict: ['PAY', 'BLOCK', 'REVIEW'][Number(verdict)] ?? String(verdict),
    reason,
    code: guardReasonCode(reason),
  });
}

// pull the custom error name out of a viem revert (NotAgent, Denied, ...). the
// point of the beat is WHICH error fires, so "it reverted" isn't enough.
function revertName(err) {
  const revert = typeof err.walk === 'function'
    ? err.walk((e) => e instanceof ContractFunctionRevertedError)
    : null;
  if (!revert?.data) return null;
  const args = revert.data.args?.length
    ? `(${revert.data.args.map((a) => (typeof a === 'bigint' ? String(a) : a)).join(', ')})`
    : '()';
  // and the same refusal in the vocabulary the off-chain rail uses, where the
  // contract has one. Denied carries a reason string instead, and that is read
  // by guardReasonCode where the verdict is printed.
  const code = guardErrorCode(revert.data.errorName);
  return `${revert.data.errorName}${args}${code ? ` / ${code}` : ''}`;
}

async function main() {
  const flags = process.argv.slice(2).filter((a) => a.startsWith('--'));
  const stay = flags.includes('--stay');
  const restoreOnly = flags.includes('--restore');
  const positional = process.argv.slice(2).find((a) => !a.startsWith('--'));

  const { walletClient, account } = requireWallet();
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const abi = compileGuard().abi;
  const agent = positional ? assertAddress('agent', positional) : account.address;

  const read = (functionName, args = []) =>
    publicClient.readContract({ address: guard, abi, functionName, args });
  const write = async (functionName, args) => {
    const hash = await walletClient.writeContract({ address: guard, abi, functionName, args, account });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    return { hash, url: txUrl(hash), status: receipt.status };
  };

  // Putting the agent back is the half of this script nobody watches: by the
  // time it runs the demo has said what it came to say, and the operator is
  // reading the beats above rather than the last line. So it is confirmed the
  // same way the revoke is, and for a better reason - the receipt has to say
  // success AND the chain has to agree the agent is authorized again. A
  // transaction that is accepted and then reverts would otherwise print
  // "restored" over an agent that is still shut off, and the run ends, the
  // shell closes, and nothing pays again until somebody works out why.
  const restore = async () => {
    const tx = await write('setAgent', [agent, true]);
    const isAgent = await read('isAgent', [agent]);
    return { ...tx, isAgent, ok: tx.status === 'success' && isAgent === true };
  };

  const [owner, authorized, limit] = await Promise.all([
    read('owner'),
    read('isAgent', [agent]),
    read('dailyLimit'),
  ]);

  // the kill switch is an owner power, and this key either has it or doesn't.
  // failing here rather than at the transaction keeps the beat honest: an
  // operator who cannot revoke needs to know that before the incident, not
  // during it.
  if (owner.toLowerCase() !== account.address.toLowerCase()) {
    console.log(`\nthis wallet (${account.address}) is not the guard's owner (${owner}).`);
    console.log('only the owner can revoke an agent. run this with the owner key.\n');
    process.exit(1);
  }

  if (restoreOnly) {
    if (authorized) {
      console.log(`\n${agent} is already an authorized agent. nothing to restore.\n`);
      return;
    }
    console.log(`\nre-authorizing ${agent} ...`);
    const tx = await restore();
    console.log(`  setAgent(${agent}, true)  ${tx.url}`);
    console.log(`  isAgent: ${tx.isAgent}`);
    if (!tx.ok) {
      // this command exists to be run during an incident, so it exits non-zero
      // rather than leaving a shell script upstream of it thinking it worked.
      console.log(`\n  !! ${agent} is STILL revoked (receipt: ${tx.status}). it cannot pay.\n`);
      process.exit(1);
    }
    console.log('');
    return;
  }

  if (!authorized) {
    console.log(`\n${agent} is not an authorized agent right now - already revoked, or never wired up.`);
    console.log('there is nothing to shut off. to put it back:  npm run kill-switch -- --restore\n');
    return;
  }

  const recipient = assertAddress('GOOD_RECIPIENT', addresses.good);
  const value = parseUnits(String(AMOUNT), 6);

  console.log(`\nAegis kill switch on the treasury rail`);
  console.log(`  guard:      ${guard}`);
  console.log(`  owner:      ${owner}  (this key)`);
  console.log(`  agent:      ${agent}`);
  console.log(`  daily cap:  ${limit === 0n ? 'off' : `${fmt(limit)} USDC`}`);

  let revoked = false;

  // Ctrl-C between the revoke and the restore leaves the agent revoked, and a
  // signal handler is the wrong place to start a transaction - it would race the
  // one already in flight. So say the single command that puts it back instead,
  // and let the operator run it when the shell is theirs again.
  process.on('SIGINT', () => {
    if (revoked && !stay) {
      console.log(`\n\n  interrupted with ${agent} still revoked. put it back with:`);
      console.log('    npm run kill-switch -- --restore');
    }
    process.exit(130);
  });

  try {
    // ---- beat 1: nothing is wrong yet ----
    beat(1, 'the agent is authorized, and this payment is fine');
    const [verdict, reason] = await read('assess', [recipient, value]);
    console.log(`  assess(${recipient}, ${AMOUNT} USDC)`);
    console.log(`    -> ${assessment(verdict, reason)}`);

    // eth_call against exactly the state a transaction would see. nothing is
    // broadcast and nothing moves - the beat is about what changes in beat 3,
    // and spending the treasury to prove a payment works would be theatre.
    let wouldPay = false;
    try {
      await publicClient.simulateContract({
        address: guard, abi, functionName: 'guardedPay', args: [recipient, value], account,
      });
      wouldPay = true;
      console.log(`  guardedPay(${AMOUNT} USDC) simulated against live state -> it would go through.`);
    } catch (err) {
      // an honest failure here is not the beat failing, it is the setup being
      // different from what the beat assumes. say which.
      console.log(`  guardedPay(${AMOUNT} USDC) would NOT go through even now: ${revertName(err) || err.shortMessage || err.message}`);
      console.log('  (the revocation below still demonstrates itself - but this run cannot');
      console.log('   show the before/after, because the payment was already failing.)');
    }

    // ---- beat 2: the owner pulls the switch ----
    beat(2, 'the agent looks compromised, and the owner revokes it live');
    console.log('  no redeploy, no migration, no pausing the whole contract:');
    console.log(`  -> setAgent(${agent}, false)`);
    const started = Date.now();
    const tx = await write('setAgent', [agent, false]);
    revoked = true;
    const seconds = ((Date.now() - started) / 1000).toFixed(1);
    if (tx.status !== 'success') {
      throw new Error(`setAgent(${agent}, false) did not succeed: ${tx.url}`);
    }
    console.log(`  CONFIRMED in ${seconds}s  ${tx.url}`);
    const stillAuthorized = await read('isAgent', [agent]);
    console.log(`  isAgent(${agent}) is now ${stillAuthorized}.`);
    if (stillAuthorized) {
      throw new Error('the revoke transaction succeeded but isAgent is still true - stopping here.');
    }

    // ---- beat 3: the same payment, refused on the caller ----
    beat(3, 'the same payment, unchanged, is now refused');
    const [after, afterReason] = await read('assess', [recipient, value]);
    console.log(`  assess(${recipient}, ${AMOUNT} USDC)`);
    console.log(`    -> ${assessment(after, afterReason)}   <- policy did not change`);

    let named = null;
    try {
      await publicClient.simulateContract({
        address: guard, abi, functionName: 'guardedPay', args: [recipient, value], account,
      });
      console.log('\n  !! it still simulates as payable. that should not happen after a revoke.');
    } catch (err) {
      named = revertName(err) || err.shortMessage || err.message;
      console.log(`  guardedPay(${AMOUNT} USDC) now reverts with: ${named}`);
    }

    // and put a real failed transaction on-chain, the way the drain beat does,
    // so the refusal is something a judge can open rather than take our word for.
    // manual gas so the wallet does not pre-flight estimateGas and refuse to
    // broadcast a call it knows will revert.
    if (named) {
      try {
        const hash = await walletClient.writeContract({
          address: guard, abi, functionName: 'guardedPay', args: [recipient, value],
          account, gas: 200_000n,
        });
        const receipt = await publicClient.waitForTransactionReceipt({ hash });
        console.log(`  broadcast anyway: ${receipt.status === 'reverted' ? 'REVERTED on-chain' : 'CONFIRMED (unexpected)'}  ${txUrl(hash)}`);
      } catch (err) {
        console.log(`  the node rejected it before it could be mined: ${err.shortMessage || err.message}`);
      }
    }

    if (wouldPay) {
      console.log('\n  Same caller, same recipient, same amount. The guard still says the');
      console.log('  recipient is clear - and the payment is refused anyway, because the');
      console.log('  agent check is the first line of guardedPay and assess() never runs.');
      console.log('  That is what makes this a kill switch and not another rule: it does not');
      console.log('  need anything about the payment to look wrong.');
    }

    // ---- beat 4: the edges, said out loud ----
    beat(4, 'what one revoke does and does not cover');
    console.log('  - it stops the treasury rail completely. guardedPay is the only way the');
    console.log('    guard moves money, and a revoked agent cannot call it.');
    const float = addresses.float;
    if (float) {
      const held = await usdcBalanceOf(float).catch(() => null);
      console.log(`  - it does NOT stop the x402 rail. that wallet (${float})`);
      console.log(`    signs authorizations against its own float${held == null ? '' : `, currently ${fmt(held)} USDC`},`);
      console.log('    and a signature needs no permission from the guard. the kill switch there');
      console.log('    is to stop refilling the float and rotate the key; the float on hand is');
      console.log('    the loss ceiling until you do (npm run rotate-keys).');
    } else {
      console.log('  - it does NOT stop the x402 rail: that wallet signs against its own float,');
      console.log('    and a signature needs no permission from the guard.');
    }
    console.log('  - it does not claw back anything already paid. this is a valve, not an undo.');
    console.log('  - it does not stop the agent burning its own gas balance, which on Arc is');
    console.log('    USDC. keep that balance thin (npm run balance says how thin).');
    console.log('  - and it is only as good as the owner key. whoever holds that can revoke,');
    console.log('    and can also un-revoke. see THREAT-MODEL.md item 3.');
    console.log('');
    console.log('  One trap worth knowing, because it reads the other way round:');
    console.log('  setDailyLimit(0) does NOT freeze spending. In this contract 0 means the cap');
    console.log('  is OFF, so reaching for it in a panic removes the only rate limit there is.');
    console.log('  To freeze payments without revoking, set the limit to 1 base unit:');
    console.log('    setDailyLimit(1)  - every payment worth making is then over the cap.');
  } finally {
    // read the chain rather than trust the flag. if the revoke landed and
    // something after it threw, `revoked` can be stale in the direction that
    // matters most - the one where we walk away leaving the agent shut off.
    let shutOff = revoked;
    try {
      shutOff = !(await read('isAgent', [agent]));
    } catch {
      // no answer from the node; the flag is the best we have
    }

    if (shutOff && !stay) {
      console.log('\n----------------------------------------------');
      try {
        const back = await restore();
        if (back.ok) {
          console.log(`  restored: setAgent(${agent}, true)  ${back.url}`);
          console.log(`  isAgent: ${back.isAgent}  - the demo left the guard as it found it.`);
          console.log('  (run with --stay to revoke for real and leave it revoked.)');
        } else {
          console.log(`  !! THE RESTORE DID NOT TAKE: receipt ${back.status}, isAgent ${back.isAgent}`);
          console.log(`  !! ${back.url}`);
          console.log(`  !! ${agent} is still revoked. put it back with:`);
          console.log('  !!   npm run kill-switch -- --restore');
        }
      } catch (err) {
        console.log(`  !! COULD NOT RESTORE THE AGENT: ${err.shortMessage || err.message}`);
        console.log(`  !! ${agent} is still revoked. put it back with:`);
        console.log('  !!   npm run kill-switch -- --restore');
      }
      console.log('----------------------------------------------\n');
    } else if (shutOff) {
      console.log('\n----------------------------------------------');
      console.log(`  ${agent} is revoked and staying revoked.`);
      console.log('  to re-authorize it when the incident is over:');
      console.log('    npm run kill-switch -- --restore');
      console.log('----------------------------------------------\n');
    }
  }
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

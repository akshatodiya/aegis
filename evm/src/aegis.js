// the decision engine. deterministic lanes first, llm only if we're
// alarmed or unsure. spits out one of PAY / BLOCK / ASK_HUMAN.
//
//   all clean            -> PAY   (no llm, fast + free)
//   reputation denylist  -> BLOCK (hard rule, no llm)
//   bytecode HIGH        -> ask llm to reason over the code
//        confirms bad    -> BLOCK
//        says benign      -> ASK_HUMAN (deterministic + llm disagree, let a human look)
//   uncertain (amount)   -> llm explains it -> ASK_HUMAN
import { checkBytecode } from './lanes/bytecode.js';
import { checkReputation } from './lanes/reputation.js';
import { checkBehavior } from './lanes/behavior.js';
import { reason } from './reasoning.js';
import { REFUSAL } from './refusals.js';

export const DECISION = {
  PAY: 'PAY',
  BLOCK: 'BLOCK',
  ASK_HUMAN: 'ASK_HUMAN',
};

export async function aegisCheck(recipient, amount, opts = {}) {
  // isApprove: we're granting an allowance, not sending funds. the risk is a
  // bit different (see the EOA case below), so the engine needs to know.
  const { isApprove = false } = opts;

  // lanes 1 and 3 read real chain state (recipient code, and the guard's own
  // Paid history); lane 2 is still a sync mock over real on-chain lists
  const bytecode = await checkBytecode(recipient);
  const reputation = checkReputation(recipient);
  const behavior = await checkBehavior(recipient, amount);

  const lanes = { bytecode, reputation, behavior };
  const reasons = [];
  let decision;
  let llm = null;
  // the machine-readable half of `reasons`, set on the same branch that decides.
  // null on a PAY: a code says why this wasn't simply paid, so a payment that
  // was simply paid has nothing to name. see src/refusals.js.
  let code = null;

  if (reputation.listed === 'deny') {
    // known bad, no point spending an llm call
    decision = DECISION.BLOCK;
    code = REFUSAL.DENYLISTED;
    reasons.push(`Reputation: ${reputation.reason}`);
  } else if (bytecode.level === 'HIGH') {
    // alarmed -> let the llm decide if it's a real trap or a false alarm
    reasons.push(`Bytecode flagged HIGH: ${bytecode.reason}`);
    reasons.push('Escalating to LLM to reason over the bytecode...');
    llm = await reason({ recipient, bytecode: bytecode.code, hits: bytecode.hits, mode: 'confirm' });

    if (!llm.available) {
      // llm down -> trust the deterministic alarm rather than crash
      decision = DECISION.BLOCK;
      code = REFUSAL.HIGH_BYTECODE;
      reasons.push(`LLM unavailable (${llm.error}); falling back to deterministic BLOCK.`);
    } else if (llm.malicious) {
      decision = DECISION.BLOCK;
      code = REFUSAL.HIGH_BYTECODE;
      reasons.push(`LLM confirms malicious (${llm.confidence}): ${llm.reason}`);
    } else {
      // llm thinks it's fine but the filter didn't - don't auto-block, ask a human
      decision = DECISION.ASK_HUMAN;
      code = REFUSAL.LANES_DISAGREE;
      reasons.push(`LLM says likely benign (${llm.confidence}): ${llm.reason}`);
      reasons.push('   (deterministic filter disagreed - surfacing both views to a human.)');
    }
  } else if (bytecode.level === 'MEDIUM') {
    // not an outright trap, but not clearly safe either (proxy, delegatecall,
    // create2, 7702 delegation). don't wave it through - have the llm explain
    // the contract and let a human make the call.
    reasons.push(`Bytecode flagged MEDIUM: ${bytecode.reason}`);
    reasons.push('Asking LLM to analyze the contract for the human...');
    llm = await reason({ recipient, bytecode: bytecode.code, hits: bytecode.hits, mode: 'analyze' });
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.MEDIUM_BYTECODE;
    if (llm.available) {
      reasons.push(`LLM summary (${llm.confidence}): ${llm.reason}`);
    } else {
      reasons.push(`   (LLM unavailable: ${llm.error} - escalating on deterministic grounds.)`);
    }
  } else if (behavior.escalate) {
    // unsure -> have the llm explain the recipient so the human decides informed
    reasons.push(`Behavior: ${behavior.reason}`);
    reasons.push('Asking LLM to analyze the recipient for the human...');
    llm = await reason({ recipient, bytecode: bytecode.code, hits: bytecode.hits, mode: 'analyze' });
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.UNUSUAL_AMOUNT;
    if (llm.available) {
      reasons.push(`LLM summary (${llm.confidence}): ${llm.reason}`);
    } else {
      reasons.push(`   (LLM unavailable: ${llm.error} - escalating on deterministic grounds.)`);
    }
  } else if (isApprove && !bytecode.isContract) {
    // approving a plain wallet. a legit spender is almost always a contract
    // (a router, an escrow); an open-ended allowance to an EOA is a classic
    // phishing pattern, so pause for a human instead of auto-approving.
    decision = DECISION.ASK_HUMAN;
    code = REFUSAL.EOA_ALLOWANCE;
    reasons.push('Approving a plain wallet (EOA). Real spenders are normally contracts, so an allowance to an EOA is a common phishing pattern.');
    reasons.push('   Surfacing to a human before the allowance is granted.');
  } else {
    // nothing tripped -> just go through
    decision = DECISION.PAY;
    if (bytecode.isContract && bytecode.score > 0) {
      // minor flags that stayed under the risk threshold - don't dump the whole
      // danger list above a green banner, just say it's below threshold.
      reasons.push(`Bytecode: minor flags below the risk threshold (${Object.keys(bytecode.hits).join(', ')}).`);
    } else {
      reasons.push(`Bytecode: ${bytecode.reason}`);
    }
    if (reputation.listed === 'allow') reasons.push(`Reputation: ${reputation.reason}`);
  }

  return { decision, code, reasons, lanes, llm, recipient, amount };
}

function banner(decision) {
  return {
    PAY: '\x1b[42m\x1b[30m  PAY  \x1b[0m',
    BLOCK: '\x1b[41m\x1b[37m  BLOCK  \x1b[0m',
    ASK_HUMAN: '\x1b[43m\x1b[30m  ASK_HUMAN  \x1b[0m',
  }[decision];
}

export function printVerdict(result) {
  const { decision, code, reasons, recipient, amount } = result;
  console.log('\n----------------------------------------------');
  console.log(`  AEGIS verdict for ${recipient}`);
  console.log(`  amount: ${amount} USDC`);
  console.log('----------------------------------------------');
  // the code next to the banner, not instead of it: one is for grepping and one
  // is for reading, and the sentences underneath are still the real answer.
  console.log(`  ${banner(decision)}${code ? `  ${code}` : ''}\n`);
  for (const r of reasons) console.log(`  ${r}`);
  console.log('----------------------------------------------\n');
}

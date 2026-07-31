// talks to the deployed AegisGuard contract.
// assess() is a read (the contract's own verdict), guardedPay() actually moves
// USDC from the treasury through the guard, and setupGuard() does the one-time
// wiring: treasury approves the guard for USDC and the owner whitelists the
// caller as an agent.
import { parseUnits, formatUnits, erc20Abi, keccak256 } from 'viem';
import { publicClient, requireWallet, addresses, assertAddress, txUrl, account } from './config.js';
import { compileGuard } from './compile.js';
import { guardReasonCode } from './refusals.js';

const VERDICT = ['PAY', 'BLOCK', 'REVIEW']; // matches enum Verdict order

let _abi = null;
function guardAbi() {
  if (!_abi) _abi = compileGuard().abi;
  return _abi;
}

function guardAddress() {
  return assertAddress('AEGIS_GUARD', addresses.guard);
}

// the contract's own verdict for this payment, read-only (no tx).
export async function assessOnChain(to, amount) {
  const guard = guardAddress();
  const value = parseUnits(String(amount), 6);
  const [verdict, reason] = await publicClient.readContract({
    address: guard,
    abi: guardAbi(),
    functionName: 'assess',
    args: [to, value],
  });
  // the contract answers in prose, because it was written and verified before
  // the codes existed. mapping its five strings here means an on-chain BLOCK for
  // a denylisted recipient and an off-chain one carry the same word, which is
  // the only way "two rails, one policy engine" is checkable rather than a
  // slogan. anything the map doesn't recognize comes back UNKNOWN, never a
  // near-match. see src/refusals.js.
  return { verdict: VERDICT[verdict] ?? String(verdict), reason, code: guardReasonCode(reason) };
}

// one way to print an on-chain verdict, so the several places that print one all
// say it the same way: the verdict, the code beside it, and the contract's own
// prose in brackets. the prose is what the contract actually stores.
export function formatAssessment({ verdict, reason, code }) {
  return `${verdict}${code ? ` / ${code}` : ''} (${reason})`;
}

// one-time setup: approve the guard to pull USDC from us (the treasury) and
// whitelist us as an agent allowed to trigger payments.
export async function setupGuard(allowanceUSDC = 1000) {
  const { walletClient, account } = requireWallet();
  const guard = guardAddress();
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);

  console.log(`  -> approving guard ${guard} for ${allowanceUSDC} USDC ...`);
  const approveHash = await walletClient.writeContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'approve',
    args: [guard, parseUnits(String(allowanceUSDC), 6)],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: approveHash });

  console.log(`  -> authorizing agent ${account.address} ...`);
  const agentHash = await walletClient.writeContract({
    address: guard,
    abi: guardAbi(),
    functionName: 'setAgent',
    args: [account.address, true],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: agentHash });

  console.log('  -> guard ready.');
}

// move `amount` USDC from the treasury to `to` through the guard. reverts
// on-chain if the guard's policy is not PAY.
export async function guardedPay(to, amount) {
  const { walletClient, account } = requireWallet();
  const guard = guardAddress();
  const value = parseUnits(String(amount), 6);

  console.log(`  -> guardedPay ${amount} USDC to ${to} via guard ${guard} ...`);
  const hash = await walletClient.writeContract({
    address: guard,
    abi: guardAbi(),
    functionName: 'guardedPay',
    args: [to, value],
    account,
  });

  console.log(`  -> tx submitted: ${hash}`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const url = txUrl(hash);
  console.log(`  -> ${receipt.status === 'success' ? 'CONFIRMED' : 'REVERTED'}  ${url}`);

  return { hash, status: receipt.status, url };
}

// ---- JIT float: the on-chain teeth under the x402 rail ----
//
// x402 payments settle off the mempool: the agent signs an EIP-3009
// authorization and a facilitator pulls USDC from the agent's OWN wallet -
// guardedPay is never in that path, so the on-chain guard can't revert an x402
// payment. Enforcement there splits by what each layer can actually see:
//   - QUALITATIVE policy (denylist / blocked-codehash / unvetted-contract vetting)
//     is re-run OFF-chain in the signer hook (src/x402/signer.js runs aegisCheck
//     on the real payTo). The guard's own on-chain lists do NOT reach the x402
//     rail - the refill below pays the float wallet, not the merchant, so
//     assess() never sees the merchant. The signer is that check for x402.
//   - RATE is bounded on-chain: the x402 wallet never holds the treasury, only a
//     small *float*, refilled ONLY through guardedPay - which is metered by the
//     daily limit.
//
// Honest guarantee (not "can't be drained"): a compromised signer can spend the
// whole current float in one shot, so instantaneous loss <= `target`; and it can
// keep spending up to `dailyLimit` per day for as long as it stays compromised
// AND funded. So the bound is a loss *rate* - at most (float + dailyLimit)/day -
// with the refill line as the kill-switch: stop ensureFloat + rotate the wallet
// on suspicion and total loss caps at the current float. It is an allowance, not
// a vault. (We keep target <= dailyLimit below so a single drain never exceeds
// the daily bound, and only ever top *up to* target so the float never
// accumulates past it across days.)
//
// Invariant that keeps the cap accounting complete: the x402 wallet SIGNS, never
// SENDS. In exact-scheme x402 the facilitator pays gas, so the float wallet never
// spends USDC-gas out of band; if it ever submitted a tx itself, gas would drain
// the float outside the cap.

// the guarded USDC balance of an address, in 6-decimal base units.
export async function usdcBalanceOf(who) {
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  return publicClient.readContract({
    address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [who],
  });
}

// pure top-up decision, so the branch logic is testable without a chain. all
// amounts are 6-dec base units. we refill only once the float dips below `min`
// (not before every payment), and when we do we top it back up to `target`.
export function floatPlan({ balance, target, min }) {
  if (min > target) throw new Error(`float min (${min}) cannot exceed target (${target})`);
  if (balance >= min) return { topUp: false, amount: 0n };
  return { topUp: true, amount: target - balance };
}

// keep the x402 wallet's float above `min` by topping it up to `target` USDC,
// but ONLY through guardedPay - so the refill is itself subject to the on-chain
// daily limit. `target`/`min` are decimal USDC (e.g. 5 = 5 USDC); comparison is
// in base units. if the top-up would cross the daily cap, guardedPay reverts on
// chain and this throws - which is the point: the cap governs x402 spend too.
export async function ensureFloat(wallet, { target, min } = {}) {
  assertAddress('X402_WALLET', wallet);
  if (target == null) throw new Error('ensureFloat needs a target float amount');
  const targetUnits = parseUnits(String(target), 6);
  const minUnits = parseUnits(String(min ?? target), 6);

  // single-shot exposure == the float, and the float tops out at `target`. keep
  // that under the daily cap so one drain can never exceed the daily bound. a
  // limit of 0 means the cap is off, so there's nothing to check against.
  const limit = await publicClient.readContract({
    address: guardAddress(), abi: guardAbi(), functionName: 'dailyLimit',
  });
  if (limit !== 0n && targetUnits > limit) {
    throw new Error(
      `ensureFloat: target ${target} USDC exceeds the guard's daily limit ${formatUnits(limit, 6)} - ` +
      `a single float drain could then exceed the daily bound. lower target to <= the limit.`,
    );
  }

  const balance = await usdcBalanceOf(wallet);
  const plan = floatPlan({ balance, target: targetUnits, min: minUnits });
  if (!plan.topUp) {
    return { toppedUp: false, balance, funded: 0n };
  }

  const amount = formatUnits(plan.amount, 6);
  console.log(
    `  -> x402 float ${formatUnits(balance, 6)} USDC below ${min ?? target}; refilling ${amount} through the guard ...`,
  );
  const pay = await guardedPay(wallet, amount); // metered by the daily cap
  // `target` is the intended post-refill float, not a re-read balance.
  return { toppedUp: true, target: targetUnits, funded: plan.amount, amount, pay };
}

// ---- the agent's gas float ----
//
// on Arc gas IS USDC, so the agent's native balance is real money the guard
// never sees. and it cannot see it: the EVM deducts gas from the sender before
// guardedPay's first opcode runs, so there is no point in the call where the
// contract could refuse. we looked at counting gas inside the daily cap and
// dropped it for two reasons - a revert doesn't refund gas already burnt (so
// the one case worth catching is the one that records nothing), and metering an
// agent-chosen tx.gasprice into a shared cap would let one agent lock every
// other agent out of the day's budget for free.
//
// what IS enforceable is how much is in the wallet to burn. so the agent's gas
// balance gets the same treatment as the x402 float: keep it thin, top it up on
// a schedule, and treat a fat balance as exposure rather than convenience. an
// agent holding 0.05 USDC of gas cannot burn 50 USDC of gas however it's
// hijacked.
//
// deliberately advisory, not blocking: a native top-up isn't an ERC-20
// transferFrom, so unlike ensureFloat it can't be routed through guardedPay and
// metered by the cap. saying otherwise would be the same overstatement we
// avoided by not counting gas on-chain.

// pure decision, 18-decimal native units (Arc's gas token). same shape as
// floatPlan, plus the direction that actually matters for a firewall: how far
// ABOVE the intended float the wallet is sitting, which is the loss ceiling if
// the key leaks.
export function gasFloatPlan({ balance, target, min }) {
  if (min > target) throw new Error(`gas float min (${min}) cannot exceed target (${target})`);
  if (balance > target) return { topUp: false, amount: 0n, exposure: balance - target };
  if (balance >= min) return { topUp: false, amount: 0n, exposure: 0n };
  return { topUp: true, amount: target - balance, exposure: 0n };
}

// read the agent's native (gas) balance and say where it stands against the
// intended float. `target`/`min` are decimal USDC, e.g. 0.05.
export async function checkGasFloat(who, { target, min } = {}) {
  const wallet = assertAddress('agent address', who ?? account?.address);
  if (target == null) throw new Error('checkGasFloat needs a target float amount');
  const targetUnits = parseUnits(String(target), 18); // native USDC is 18-dec
  const minUnits = parseUnits(String(min ?? target), 18);

  const balance = await publicClient.getBalance({ address: wallet });
  const plan = gasFloatPlan({ balance, target: targetUnits, min: minUnits });
  const held = formatUnits(balance, 18);

  // the sharper version of the same risk. on Arc the ERC-20 is a 6-decimal view
  // over the native balance, so if this wallet is also the treasury then every
  // USDC the guard meters through transferFrom is simultaneously burnable as
  // uncapped gas by the same key, and the daily limit governs one of the two
  // ways to spend it. this is the argument .env.example already makes about the
  // x402 key, one rail over.
  let isTreasury = false;
  try {
    const treasury = await publicClient.readContract({
      address: guardAddress(), abi: guardAbi(), functionName: 'treasury',
    });
    isTreasury = treasury.toLowerCase() === wallet.toLowerCase();
  } catch {
    // no guard wired up yet - the float advice below still stands on its own
  }
  if (isTreasury) {
    console.log(
      `  !! this wallet is also the guard's treasury, so the whole guarded balance ` +
      `is burnable as gas outside the daily cap. run the agent on its own key and ` +
      `leave the treasury holding the funds.`,
    );
  } else if (plan.exposure > 0n) {
    console.log(
      `  !! agent gas balance ${held} USDC is above the ${target} float ` +
      `(${formatUnits(plan.exposure, 18)} over). that surplus is burnable by a hijacked key ` +
      `and no on-chain rule can stop it - sweep it back to the treasury.`,
    );
  } else if (plan.topUp) {
    console.log(`  -> agent gas balance ${held} USDC is below ${min ?? target}; top up to ${target} to keep paying gas.`);
  }
  return { ...plan, balance, wallet };
}

// the bridge between the two layers. once the off-chain analyzer (opcode scan +
// llm) is sure a recipient is malicious, we write that conclusion into the
// guard's own on-chain state, so from now on the contract blocks it by itself -
// even for an agent that never runs the off-chain check. note this only ever
// *tightens* policy (it writes blocklists, never the allowlist), so the worst a
// bad call can do is a false block, which the owner can undo with one tx.
//
// a real contract is blocked by codehash: that kills every address running the
// exact same bytecode, not just this one deployment. a plain wallet (or an
// EIP-7702 delegated EOA, which also carries code) has no code family we'd want
// to block wholesale, so it's denylisted by address instead. both setters are
// onlyOwner on-chain, so this needs the guard owner's key. in this deployment
// the deployer is owner + agent; the treasury was split onto its own key so the
// guarded funds aren't burnable as gas (see rotate-keys and THREAT-MODEL item 1).
export async function recordVerdictOnChain(to) {
  const { walletClient, account } = requireWallet();
  const guard = guardAddress();

  const code = await publicClient.getCode({ address: to });
  // eip-7702 delegated EOA: getCode returns 0xef0100 || <delegate>. that
  // "codehash" is shared by every account pointing at the same delegate, so
  // blocking it would take out unrelated wallets. treat it as an EOA.
  const lower = (code || '0x').toLowerCase();
  const isRealContract = lower !== '0x' && !lower.startsWith('0xef0100');

  try {
    if (isRealContract) {
      const codehash = keccak256(code);
      // idempotency: read the exact slot we're about to write, not assess() - the
      // address could already be blocked for some other reason while this
      // codehash isn't, and we'd wrongly skip recording the code family.
      const already = await publicClient.readContract({
        address: guard, abi: guardAbi(), functionName: 'blockedCodehash', args: [codehash],
      });
      if (already) {
        return { changed: false, message: `already blocked on-chain (bytecode ${codehash.slice(0, 10)}...) - recorded on an earlier run.` };
      }
      console.log(`  -> setBlockedCodehash(${codehash.slice(0, 10)}...) ...`);
      const hash = await walletClient.writeContract({
        address: guard, abi: guardAbi(), functionName: 'setBlockedCodehash', args: [codehash, true], account,
      });
      await publicClient.waitForTransactionReceipt({ hash });
      return { changed: true, message: `blocked its bytecode ${codehash.slice(0, 10)}... on-chain (kills every clone of this exact code).`, hash };
    }

    const already = await publicClient.readContract({
      address: guard, abi: guardAbi(), functionName: 'denylisted', args: [to],
    });
    if (already) {
      return { changed: false, message: `already denylisted on-chain - recorded on an earlier run.` };
    }
    console.log(`  -> setDenylisted(${to}) ...`);
    const hash = await walletClient.writeContract({
      address: guard, abi: guardAbi(), functionName: 'setDenylisted', args: [to, true], account,
    });
    await publicClient.waitForTransactionReceipt({ hash });
    return { changed: true, message: `denylisted ${to} on-chain.`, hash };
  } catch (err) {
    // e.g. run by someone who isn't the guard owner - degrade instead of crash.
    return { changed: false, message: `could not record on-chain: ${err.shortMessage || err.message}` };
  }
}

// true when `to` is a contract the guard hasn't been told to trust yet - which is
// exactly the on-chain condition behind a REVIEW of "unvetted contract recipient".
// we recompute it from state (has code, not allowlisted) rather than string-match
// the revert reason, so the two don't drift apart. an EIP-7702 EOA (0xef0100...)
// carries code but isn't a contract we'd allowlist, so it's excluded.
export async function needsVetting(to) {
  const guard = guardAddress();
  const code = await publicClient.getCode({ address: to });
  const lower = (code || '0x').toLowerCase();
  if (lower === '0x' || lower.startsWith('0xef0100')) return false;

  const allowed = await publicClient.readContract({
    address: guard, abi: guardAbi(), functionName: 'allowedContract', args: [to],
  });
  return !allowed;
}

// the allow direction of the bridge, and the mirror image of recordVerdictOnChain.
// it marks a contract as vetted (setAllowedContract) so the guard will auto-pay
// it from now on. this GRANTS trust, which is the dangerous direction - a wrong
// allow lets money out, where a wrong block only refuses a payment. so unlike
// blocking, this is never called silently: the caller (see agent.js runGuard)
// gets an explicit owner confirmation first. here we just do the owner-only write.
export async function allowlistOnChain(to) {
  const { walletClient, account } = requireWallet();
  const guard = guardAddress();

  const already = await publicClient.readContract({
    address: guard, abi: guardAbi(), functionName: 'allowedContract', args: [to],
  });
  if (already) {
    return { changed: false, message: `already allowlisted on-chain.` };
  }

  try {
    console.log(`  -> setAllowedContract(${to}) ...`);
    const hash = await walletClient.writeContract({
      address: guard, abi: guardAbi(), functionName: 'setAllowedContract', args: [to, true], account,
    });
    await publicClient.waitForTransactionReceipt({ hash });
    return { changed: true, message: `allowlisted ${to} on-chain.`, hash };
  } catch (err) {
    return { changed: false, message: `could not allowlist on-chain: ${err.shortMessage || err.message}` };
  }
}

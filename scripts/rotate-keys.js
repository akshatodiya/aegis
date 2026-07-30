// Split the one EOA that currently does everything into three roles.
//
// Why this exists: on Arc the ERC-20 at 0x3600.. is a 6-decimal view over the
// native balance, so it is ONE pot with two windows. guardedPay moves it through
// the ERC-20 window; an ordinary transaction burns it as gas through the native
// window. Gas is deducted before guardedPay's first opcode runs, so no on-chain
// rule can bound it. That means "the treasury only approves the guard" is only
// true while the treasury key never sends anything else - and today treasury,
// owner and agent are all the same key, so the daily cap governs one of two ways
// to spend the same money. Separating the roles is what makes the claim true.
//
//   treasury  holds the USDC and approves the guard. signs once, then nothing.
//   owner     sets policy (denylist, codehash blocks, limits). cold.
//   agent     hot key that calls guardedPay and pays gas. holds only a float.
//
// No redeploy: setTreasury, setAgent and the two-step ownership transfer already
// exist on the deployed contract.
//
// Two steps CANNOT be done from here, because they need the other keys:
//   - the new treasury must approve(guard, allowance) itself
//   - the new owner must call acceptOwnership() itself
// The script checks the first and prints the second, rather than pretending.
//
// Only NEW_TREASURY is required, and it is the one that matters: splitting the
// treasury off the agent is what stops the guarded funds being burnable as gas.
// NEW_AGENT and NEW_OWNER are optional and default to the current wallet, so the
// one-key version of this is a real, complete fix rather than a half measure.
//
// Note on the owner: this repo drives every write from one wallet (guardedPay is
// agent-only, setBlockedCodehash is owner-only, both use requireWallet), so
// pointing NEW_OWNER at a different key needs code changes here too. And an
// owner key living in the same .env as the agent key is separation on paper.
// Splitting the treasury needs neither.
//
// Usage (prints a plan and changes nothing):
//   NEW_TREASURY=0x.. npm run rotate-keys
// Then, to actually send the transactions:
//   NEW_TREASURY=0x.. npm run rotate-keys -- --execute
import { erc20Abi, formatUnits, isAddress } from 'viem';
import {
  publicClient, requireWallet, addresses, assertAddress, txUrl, chain,
} from '../src/config.js';
import { compileGuard } from '../src/compile.js';

const EXECUTE = process.argv.includes('--execute');

function need(name) {
  const v = process.env[name];
  if (!v || !isAddress(v)) {
    throw new Error(`${name} is missing or not an address. See the header of this file for usage.`);
  }
  return v;
}

function optional(name, fallback) {
  const v = process.env[name];
  if (v && !isAddress(v)) throw new Error(`${name} is set but is not an address: ${v}`);
  return v || fallback;
}

async function main() {
  const abi = compileGuard().abi;
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  const { walletClient, account } = requireWallet();

  const read = (functionName, args = []) =>
    publicClient.readContract({ address: guard, abi, functionName, args });

  const [owner, treasury] = await Promise.all([read('owner'), read('treasury')]);
  console.log(`\nGuard ${guard} on ${chain.name}`);
  console.log(`  owner    ${owner}`);
  console.log(`  treasury ${treasury}`);
  console.log(`  caller   ${account.address}\n`);

  if (owner.toLowerCase() !== account.address.toLowerCase()) {
    throw new Error(`only the owner can rotate roles, and this wallet is not it (owner is ${owner}).`);
  }

  const newTreasury = need('NEW_TREASURY');
  const newAgent = optional('NEW_AGENT', account.address);
  const newOwner = optional('NEW_OWNER', owner);

  // the one overlap that actually matters. on Arc the ERC-20 is a view over the
  // native balance, so a key that is both treasury and agent can burn the
  // guarded funds as gas, uncapped, with nothing on-chain able to refuse.
  if (newTreasury.toLowerCase() === newAgent.toLowerCase()) {
    throw new Error('treasury and agent cannot be the same address - that is the hole this script exists to close.');
  }
  // owner == agent is today's disclosed limitation, not a blocker: this repo
  // signs owner writes and agent writes with the same wallet, so splitting it
  // needs code changes too. say so rather than silently allowing it.
  if (newOwner.toLowerCase() === newAgent.toLowerCase()) {
    console.log('  note: owner and agent remain the same key. that is the known limitation in');
    console.log('        THREAT-MODEL.md - policy writes and payments share a wallet. splitting');
    console.log('        it needs a separate owner wallet in guard.js, not just this script.\n');
  }

  // the new treasury must already be funded AND have approved the guard, or
  // setTreasury would point the guard at a wallet it cannot pull from and every
  // guardedPay would start failing. check before touching anything.
  const [bal, allowance] = await Promise.all([
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [newTreasury] }),
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'allowance', args: [newTreasury, guard] }),
  ]);
  const gas = await publicClient.getBalance({ address: newAgent });

  console.log('Preconditions:');
  console.log(`  new treasury USDC        ${formatUnits(bal, 6)}`);
  console.log(`  new treasury -> guard    ${formatUnits(allowance, 6)} approved`);
  console.log(`  new agent gas balance    ${formatUnits(gas, chain.nativeCurrency.decimals)} ${chain.nativeCurrency.symbol}\n`);

  const problems = [];
  if (allowance === 0n) {
    problems.push(
      'the new treasury has not approved the guard. from the TREASURY key, send:\n' +
      `      approve(${guard}, <allowance>) on USDC ${usdc}\n` +
      '      (this is the one signature the treasury ever makes)',
    );
  }
  if (bal === 0n) problems.push('the new treasury holds no USDC - fund it first, or guardedPay has nothing to move.');
  if (gas === 0n) problems.push('the new agent has no gas - send it a thin float, it pays its own gas.');
  if (problems.length) {
    console.log('Not ready yet:');
    for (const p of problems) console.log(`  - ${p}`);
    console.log('\nFix those, then run this again.\n');
    return;
  }

  // order matters: authorise the new agent BEFORE revoking the old one, and
  // repoint the treasury only once its approval is confirmed above, so there is
  // never a window where nobody can pay.
  const keepingAgent = newAgent.toLowerCase() === account.address.toLowerCase();
  const keepingOwner = newOwner.toLowerCase() === owner.toLowerCase();
  const steps = [];

  if (!keepingAgent) steps.push(['setAgent', [newAgent, true], `authorise ${newAgent} as an agent`]);
  steps.push(['setTreasury', [newTreasury], `point the guard at treasury ${newTreasury}`]);
  // only revoke the old key if it is not the agent we are keeping - otherwise
  // this would cheerfully strip the agent it just decided to leave in place.
  if (!keepingAgent) {
    steps.push(['setAgent', [account.address, false], `revoke the old all-in-one key ${account.address}`]);
  }
  // and don't hand ownership to whoever already has it - a self transfer just
  // leaves a pending transfer nobody needs to accept.
  if (!keepingOwner) {
    steps.push(['transferOwnership', [newOwner], `hand ownership to ${newOwner} (they must accept)`]);
  }

  if (!EXECUTE) {
    console.log('Plan (nothing sent - pass --execute to run it):');
    steps.forEach(([fn, args, why], i) => console.log(`  ${i + 1}. ${fn}(${args.join(', ')})  ${why}`));
    if (keepingAgent) console.log(`  (agent stays ${account.address}, holding only a gas float)`);
    if (keepingOwner) console.log(`  (owner stays ${owner})`);
    if (!keepingOwner) {
      console.log(`\n  then, from the NEW OWNER key: acceptOwnership() on ${guard}`);
      console.log('  ownership is two-step on purpose, so a wrong address cannot brick admin.');
    }
    console.log();
    return;
  }

  for (const [functionName, args, why] of steps) {
    console.log(`  -> ${why} ...`);
    const hash = await walletClient.writeContract({ address: guard, abi, functionName, args, account });
    await publicClient.waitForTransactionReceipt({ hash });
    console.log(`     ${txUrl(hash)}`);
  }

  if (keepingOwner) {
    console.log('\nDone. The treasury is now a separate key that never sends transactions,');
    console.log('so the guarded balance is no longer burnable as gas by the agent.\n');
  } else {
    console.log('\nDone, except the last step, which only the new owner can take:');
    console.log(`  from the NEW OWNER key, call acceptOwnership() on ${guard}`);
    console.log('  until then the old key is still owner, which is the point of two-step.\n');
  }
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

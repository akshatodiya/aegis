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
// Usage (prints a plan and changes nothing):
//   NEW_TREASURY=0x.. NEW_AGENT=0x.. NEW_OWNER=0x.. npm run rotate-keys
// Then, to actually send the transactions:
//   NEW_TREASURY=0x.. NEW_AGENT=0x.. NEW_OWNER=0x.. npm run rotate-keys -- --execute
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

async function main() {
  const abi = compileGuard().abi;
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  const { walletClient, account } = requireWallet();

  const newTreasury = need('NEW_TREASURY');
  const newAgent = need('NEW_AGENT');
  const newOwner = need('NEW_OWNER');

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

  // three distinct roles, or the whole exercise is theatre
  const roles = { treasury: newTreasury, agent: newAgent, owner: newOwner };
  const seen = new Map();
  for (const [role, addr] of Object.entries(roles)) {
    const k = addr.toLowerCase();
    if (seen.has(k)) throw new Error(`${role} and ${seen.get(k)} are the same address - that defeats the split.`);
    seen.set(k, role);
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
  const steps = [
    ['setAgent', [newAgent, true], `authorise ${newAgent} as an agent`],
    ['setTreasury', [newTreasury], `point the guard at treasury ${newTreasury}`],
    ['setAgent', [account.address, false], `revoke the old all-in-one key ${account.address}`],
    ['transferOwnership', [newOwner], `hand ownership to ${newOwner} (they must accept)`],
  ];

  if (!EXECUTE) {
    console.log('Plan (nothing sent - pass --execute to run it):');
    steps.forEach(([fn, args, why], i) => console.log(`  ${i + 1}. ${fn}(${args.join(', ')})  ${why}`));
    console.log(`\n  then, from the NEW OWNER key: acceptOwnership() on ${guard}`);
    console.log('  ownership is two-step on purpose, so a wrong address cannot brick admin.\n');
    return;
  }

  for (const [functionName, args, why] of steps) {
    console.log(`  -> ${why} ...`);
    const hash = await walletClient.writeContract({ address: guard, abi, functionName, args, account });
    await publicClient.waitForTransactionReceipt({ hash });
    console.log(`     ${txUrl(hash)}`);
  }

  console.log('\nDone, except the last step, which only the new owner can take:');
  console.log(`  from the NEW OWNER key, call acceptOwnership() on ${guard}`);
  console.log('  until then the old key is still owner, which is the point of two-step.\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

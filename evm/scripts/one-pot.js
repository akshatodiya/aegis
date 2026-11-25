// One pot, two windows.
//
// On Arc, USDC is the native gas token (18 decimals) AND an ERC-20 at
// 0x3600.. (6 decimals). It is tempting to read that as two assets that happen
// to share a name. It is not. The ERC-20 is a *view* over the same balance the
// native side spends: for any address, native / 10^12 == erc20, exactly.
//
// That matters for the guard. AegisGuard meters spending through the ERC-20
// window, with a daily cap it enforces atomically. Gas leaves through the native
// window, and the EVM takes it before the contract's first opcode runs, so there
// is no point at which any on-chain rule could refuse it - and a revert doesn't
// give back gas already burnt. Same money, two exits, one of them ungoverned.
//
// Which is why the treasury must not be the agent. This script shows the
// relationship, and with --burn it proves it by spending gas and watching both
// numbers fall together.
//
//   npm run one-pot            read-only
//   npm run one-pot -- --burn  sends a 0-value self-transaction (costs gas)
import { erc20Abi, formatUnits } from 'viem';
import {
  publicClient, account, addresses, assertAddress, chain, requireWallet, txUrl, waitForSuccess,
} from '../src/config.js';
import { compileGuard } from '../src/compile.js';

const BURN = process.argv.includes('--burn');
const SCALE = 10n ** 12n; // 18-dec native -> 6-dec ERC-20

async function balances(who, usdc) {
  const [native, erc20] = await Promise.all([
    publicClient.getBalance({ address: who }),
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [who] }),
  ]);
  return { native, erc20 };
}

function show(label, { native, erc20 }) {
  console.log(`  ${label}`);
  console.log(`    native (18-dec, pays gas)   ${formatUnits(native, 18)}`);
  console.log(`    ERC-20 (6-dec, the guard)   ${formatUnits(erc20, 6)}`);
  console.log(`    native / 10^12 === ERC-20   ${native / SCALE === erc20}`);
}

async function main() {
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  if (!account) throw new Error('PRIVATE_KEY missing in .env.');
  const who = account.address;

  console.log(`\nOne pot, two windows  (${chain.name})`);
  console.log(`wallet ${who}\n`);

  const before = await balances(who, usdc);
  show('right now:', before);

  // what the guard actually governs, next to what it can't
  if (addresses.guard) {
    const abi = compileGuard().abi;
    const read = (fn, args = []) => publicClient.readContract({ address: addresses.guard, abi, functionName: fn, args });
    const [limit, treasury, isAgent] = await Promise.all([
      read('dailyLimit'), read('treasury'), read('isAgent', [who]),
    ]);
    const day = await read('today');
    const spent = await read('spentOnDay', [day]);
    console.log('\n  the guard:');
    console.log(`    daily limit                 ${formatUnits(limit, 6)} USDC`);
    console.log(`    spent today                 ${formatUnits(spent, 6)} USDC`);
    console.log(`    this wallet is the treasury ${treasury.toLowerCase() === who.toLowerCase()}`);
    console.log(`    this wallet is an agent     ${isAgent}`);

    if (treasury.toLowerCase() === who.toLowerCase()) {
      console.log('\n  so: every USDC the daily limit meters through the ERC-20 window is');
      console.log('      simultaneously burnable as gas through the native window, by this');
      console.log('      same key, with nothing on-chain able to stop it. run `npm run');
      console.log('      rotate-keys` to split the treasury off the agent.');
    }
  }

  if (!BURN) {
    console.log('\n  pass --burn to spend a little gas and watch both numbers move together.\n');
    return;
  }

  // a 0-value transaction to ourselves. it moves no USDC through the ERC-20
  // window at all, and both balances still drop - because gas came out of the
  // same pot.
  const { walletClient } = requireWallet();
  console.log('\n  sending a 0-value self-transaction (moves no ERC-20, only burns gas) ...');
  const hash = await walletClient.sendTransaction({ account, to: who, value: 0n });
  const receipt = await waitForSuccess(hash, 'the transfer');
  console.log(`  ${txUrl(hash)}`);

  const after = await balances(who, usdc);
  console.log();
  show('after:', after);

  const burntNative = before.native - after.native;
  console.log('\n  moved through the ERC-20 window:  0');
  console.log(`  gas burnt (native)               ${formatUnits(burntNative, 18)}`);
  console.log(`  ERC-20 balance fell by           ${formatUnits(before.erc20 - after.erc20, 6)}`);
  console.log(`  gas used x price                 ${receipt.gasUsed} x ${receipt.effectiveGasPrice}`);
  console.log('\n  the guard saw none of this, and could not have.\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

// The one signature the treasury ever makes.
//
// After `rotate-keys` the treasury holds the funds and the guard moves them with
// transferFrom, so the treasury never signs a payment - it signs a single
// approve and then goes quiet. This script is that approve, kept separate from
// everything else on purpose: config.js deliberately never loads the treasury
// key, so nothing in the normal run path can touch it.
//
// The key goes in .env as TREASURY_PRIVATE_KEY (gitignored), is used once, and
// should then be removed from .env and kept somewhere this repo can't reach.
// It is never printed here - only the address derived from it.
//
//   npm run treasury-approve          approve exactly the treasury's balance
//   npm run treasury-approve -- 250   approve 250 USDC instead
import { createWalletClient, erc20Abi, formatUnits, parseUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { publicClient, transport, chain, addresses, assertAddress, txUrl } from '../src/config.js';

async function main() {
  const raw = process.env.TREASURY_PRIVATE_KEY;
  if (!raw || raw.trim() === '') {
    throw new Error(
      'TREASURY_PRIVATE_KEY missing in .env.\n' +
      "  Add it, run this once, then delete it from .env - it's not needed again.",
    );
  }
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);

  const account = privateKeyToAccount(raw.startsWith('0x') ? raw : `0x${raw}`);
  const wallet = createWalletClient({ account, chain, transport });

  // if NEW_TREASURY is set, the key had better be that wallet - approving from
  // the wrong one leaves the guard unable to pull and is confusing to debug.
  const expected = process.env.NEW_TREASURY;
  if (expected && expected.toLowerCase() !== account.address.toLowerCase()) {
    throw new Error(
      `this key is ${account.address} but NEW_TREASURY is ${expected}.\n` +
      '  approving from the wrong wallet would not help the guard.',
    );
  }

  const balance = await publicClient.readContract({
    address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [account.address],
  });

  // default to exactly what the treasury holds. an unlimited approval would be
  // the lazy choice and a bad look in a project about bounding blast radius.
  const arg = process.argv[2];
  const amount = arg ? parseUnits(arg, 6) : balance;
  if (amount === 0n) throw new Error('nothing to approve - the treasury holds no USDC.');

  console.log(`\ntreasury ${account.address} on ${chain.name}`);
  console.log(`  holds    ${formatUnits(balance, 6)} USDC`);
  console.log(`  approving ${formatUnits(amount, 6)} USDC to the guard ${guard} ...`);

  const hash = await wallet.writeContract({
    address: usdc, abi: erc20Abi, functionName: 'approve', args: [guard, amount], account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log(`  status ${receipt.status}`);
  console.log(`  ${txUrl(hash)}`);

  const allowance = await publicClient.readContract({
    address: usdc, abi: erc20Abi, functionName: 'allowance', args: [account.address, guard],
  });
  console.log(`\n  allowance is now ${formatUnits(allowance, 6)} USDC.`);

  // Only now is it safe to say that. This is the single most destructive piece
  // of advice in the repo: the treasury key is the ONLY thing that can grant
  // this allowance, and the whole point of the script is that it gets deleted
  // afterwards. Telling someone to delete it after a mined-but-reverted approve
  // - or after approving from a wallet whose allowance did not actually move -
  // ends with funds in a treasury the guard can never pull from and no key left
  // to fix it. waitForTransactionReceipt resolves for a reverted transaction, so
  // the read-back above is the check, not the receipt.
  if (receipt.status !== 'success' || allowance < amount) {
    console.error('\n  THE APPROVE DID NOT TAKE.');
    console.error(`  wanted an allowance of at least ${formatUnits(amount, 6)} USDC, read back ${formatUnits(allowance, 6)}.`);
    console.error('  KEEP TREASURY_PRIVATE_KEY in .env and run this again - it is the only key');
    console.error('  that can approve the guard, and without the allowance the treasury rail');
    console.error('  cannot pay at all.\n');
    process.exit(1);
  }

  console.log('  remove TREASURY_PRIVATE_KEY from .env now - the treasury is done signing.');
  console.log('  next: npm run rotate-keys   (then -- --execute)\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

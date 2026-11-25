// grants a USDC spending allowance (erc20 approve) on whatever chain config.js
// is pointed at, which is Arc unless CHAIN says otherwise.
// this is the other way an agent bleeds money: not by sending funds, but by
// approving a shady spender that drains the wallet later. so aegis runs the
// spender through the same checks as a payment recipient before we ever sign.
import { parseUnits, erc20Abi } from 'viem';
import { publicClient, requireWallet, addresses, assertAddress, txUrl } from './config.js';

// usdc is 6 decimals, cache it after the first read
let _decimals = null;
async function usdcDecimals(usdc) {
  if (_decimals !== null) return _decimals;
  try {
    _decimals = await publicClient.readContract({
      address: usdc, abi: erc20Abi, functionName: 'decimals',
    });
  } catch {
    _decimals = 6;
  }
  return _decimals;
}

// approve `spender` to move up to `amount` USDC on our behalf
export async function approveUSDC(spender, amount) {
  const { walletClient, account } = requireWallet();
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  assertAddress('spender', spender);

  const decimals = await usdcDecimals(usdc);
  const value = parseUnits(String(amount), decimals);

  console.log(`  -> approving ${spender} to spend ${amount} USDC ...`);
  const hash = await walletClient.writeContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'approve',
    args: [spender, value],
    account,
  });

  console.log(`  -> tx submitted: ${hash}`);
  console.log('  -> waiting for confirmation ...');
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const url = txUrl(hash);
  console.log(`  -> ${receipt.status === 'success' ? 'CONFIRMED' : 'REVERTED'}  ${url}`);

  return { hash, status: receipt.status, url };
}

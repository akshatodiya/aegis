// sends real USDC (erc20 transfer) on whatever chain config.js is pointed at,
// which is Arc unless CHAIN says otherwise.
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

// send `amount` USDC to recipient, wait for 1 confirmation, return the hash
export async function payUSDC(recipient, amount) {
  const { walletClient, account } = requireWallet();
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  assertAddress('recipient', recipient);

  const decimals = await usdcDecimals(usdc);
  const value = parseUnits(String(amount), decimals);

  console.log(`  -> sending ${amount} USDC to ${recipient} ...`);
  const hash = await walletClient.writeContract({
    address: usdc,
    abi: erc20Abi,
    functionName: 'transfer',
    args: [recipient, value],
    account,
  });

  console.log(`  -> tx submitted: ${hash}`);
  console.log('  -> waiting for confirmation ...');
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const url = txUrl(hash);
  console.log(`  -> ${receipt.status === 'success' ? 'CONFIRMED' : 'REVERTED'}  ${url}`);

  return { hash, status: receipt.status, url };
}

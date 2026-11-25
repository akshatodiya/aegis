// quick sanity check - print the wallet's gas + USDC balance and confirm the
// USDC address. run this first after filling .env, before touching any logic.
import { formatUnits, erc20Abi } from 'viem';
import { publicClient, account, addresses, assertAddress, chain, arcTestnet } from '../src/config.js';

async function main() {
  if (!account) {
    throw new Error('No account - fill PRIVATE_KEY in .env first.');
  }
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);

  const native = chain.nativeCurrency;
  console.log(`\nWallet: ${account.address}`);
  console.log(`Chain:  ${chain.name} (${chain.id})\n`);

  const wei = await publicClient.getBalance({ address: account.address });
  console.log(`Gas balance:  ${formatUnits(wei, native.decimals)} ${native.symbol}`);

  // read symbol/decimals too so we know we're pointing at the right token
  const [symbol, decimals, raw] = await Promise.all([
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'symbol' }),
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'decimals' }),
    publicClient.readContract({ address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [account.address] }),
  ]);

  console.log(`Token @ ${usdc}`);
  console.log(`  symbol:   ${symbol}   (expect USDC)`);
  console.log(`  decimals: ${decimals}`);
  console.log(`  balance:  ${formatUnits(raw, decimals)} ${symbol}`);

  // on Arc these two lines are one balance, not two pools: the ERC-20 at
  // 0x3600.. is a 6-decimal view over the same native USDC that pays gas.
  // worth saying out loud, because it means gas spend and guarded spend come
  // out of the same money (see THREAT-MODEL.md).
  if (chain.id === arcTestnet.id && wei / 10n ** 12n === raw) {
    console.log('\n  note: gas and the ERC-20 above are the same balance, viewed at 18 and 6 decimals.');
  }

  const ok = symbol.toUpperCase().includes('USDC') && Number(formatUnits(raw, decimals)) > 0;
  console.log(`\n${ok ? 'Looks right - USDC address confirmed and wallet funded.' : 'Check the USDC_ADDRESS / balance above.'}\n`);
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

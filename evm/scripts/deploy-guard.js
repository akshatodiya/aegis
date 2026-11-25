// compiles and deploys AegisGuard to whatever chain config.js is pointed at.
// that's Arc unless CHAIN says otherwise, and it's what put the live guard on
// Arc testnet.
//
//   node scripts/deploy-guard.js [dailyLimitUSDC]
//
// the deployer becomes owner + treasury (the address that holds the USDC and
// approves the guard). dailyLimit is the behavior-lane ceiling per day, default
// 100 USDC - spend past it comes back REVIEW. paste the printed address into
// .env as AEGIS_GUARD, then run guard-setup to approve + authorize.
import { parseUnits } from 'viem';
import { publicClient, requireWallet, addresses, assertAddress, addressUrl, waitForSuccess } from '../src/config.js';
import { compileGuard } from '../src/compile.js';

async function main() {
  const { walletClient, account } = requireWallet();
  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);

  const limitArg = process.argv[2] ? Number(process.argv[2]) : 100;
  if (!Number.isFinite(limitArg) || limitArg <= 0) {
    throw new Error(`bad daily limit: ${process.argv[2]} (USDC amount, must be positive)`);
  }
  const dailyLimit = parseUnits(String(limitArg), 6); // usdc is 6 decimals

  console.log('\nCompiling AegisGuard.sol ...');
  const { abi, bytecode } = compileGuard();

  // deployer doubles as treasury for the demo (one funded test wallet). in
  // production the treasury key stays cold and only ever approves the guard.
  const treasury = account.address;

  console.log(`Deploying guard (USDC ${usdc}, treasury ${treasury}, daily limit ${limitArg} USDC) ...`);
  const hash = await walletClient.deployContract({
    abi,
    bytecode,
    args: [usdc, treasury, dailyLimit],
    account,
  });
  console.log(`  tx: ${hash}`);

  const receipt = await waitForSuccess(hash, 'the AegisGuard deployment');
  const addr = receipt.contractAddress;

  console.log(`\nDeployed at: ${addr}`);
  console.log(`   explorer: ${addressUrl(addr)}`);
  console.log(`\nPut this in your .env:\n   AEGIS_GUARD="${addr}"`);
  console.log('Then run:  npm run guard-setup\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

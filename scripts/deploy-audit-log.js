// compiles and deploys AegisAuditLog to whatever chain config.js is pointed at,
// then authorizes this wallet as a reporter so it can actually write.
//
//   node scripts/deploy-audit-log.js
//
// the deployer becomes owner (who may authorize reporters) and its own first
// reporter (the hot agent key that refuses payments and records them). paste the
// printed address into .env as AEGIS_AUDIT_LOG.
//
// this is optional infrastructure. the log records x402 refusals after the fact
// and sits in no payment path, so nothing here changes what Aegis allows or
// refuses - skip the deploy and every demo runs the same, just without receipts.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { publicClient, requireWallet, addressUrl, txUrl, chain } from '../src/config.js';
import { compileContract, compileInput } from '../src/compile.js';

async function main() {
  const { walletClient, account } = requireWallet();

  console.log('\nCompiling AegisAuditLog.sol ...');
  const { abi, bytecode } = compileContract('AegisAuditLog.sol', 'AegisAuditLog');

  console.log(`Deploying to ${chain.name} (owner ${account.address}) ...`);
  const hash = await walletClient.deployContract({ abi, bytecode, account });
  console.log(`  tx: ${hash}`);

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const addr = receipt.contractAddress;
  console.log(`\nDeployed at: ${addr}`);
  console.log(`   explorer: ${addressUrl(addr)}`);

  // without this the contract accepts nothing from anyone - the writer has to be
  // authorized, so that a stranger cannot mint entries that look like ours.
  console.log(`\nAuthorizing ${account.address} as a reporter ...`);
  const setHash = await walletClient.writeContract({
    address: addr, abi, functionName: 'setReporter', args: [account.address, true], account,
  });
  await publicClient.waitForTransactionReceipt({ hash: setHash });
  console.log(`  ${txUrl(setHash)}`);

  // an audit log nobody can read the source of is a weaker receipt: an explorer
  // that doesn't know the ABI shows the entries as raw topics. drop the exact
  // build on disk so the source can be verified on the explorer by hand (there
  // is no api key path here the way verify-guard has one for etherscan).
  const outDir = fileURLToPath(new URL('../contracts/out/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  writeFileSync(outDir + 'AegisAuditLog.standard-input.json', JSON.stringify(compileInput('AegisAuditLog.sol')));
  console.log('\nTo verify the source on the explorer, upload:');
  console.log(`   ${outDir}AegisAuditLog.standard-input.json`);
  console.log('   solidity standard-json input, optimizer on / 200 runs, MIT, no constructor args');

  console.log(`\nPut this in your .env:\n   AEGIS_AUDIT_LOG="${addr}"`);
  console.log('Then run the x402 demo - its refusals will leave receipts:');
  console.log('   npm run x402-demo   (and npm run audit-log to read them back)\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

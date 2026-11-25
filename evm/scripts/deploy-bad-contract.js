// deploys recipient B: HoneypotVault, the demo villain. it compiles from
// contracts/HoneypotVault.sol, so the deployed code is real solidity output
// (delegatecall proxy + selfdestruct + tx.origin) rather than a toy stub.
// the bytecode lane flags it HIGH -> the engine BLOCKs paying it.
import { publicClient, requireWallet, addressUrl, waitForSuccess } from '../src/config.js';
import { compileContract } from '../src/compile.js';

// danger opcodes we expect to see in the deployed runtime (sanity check)
const DANGER = { 0xff: 'SELFDESTRUCT', 0xf4: 'DELEGATECALL', 0x32: 'ORIGIN' };

function dangerOpcodes(hex) {
  const bytes = Buffer.from(hex.slice(2), 'hex');
  const found = new Set();
  for (let i = 0; i < bytes.length; i++) {
    const op = bytes[i];
    if (op >= 0x60 && op <= 0x7f) { i += op - 0x60 + 1; continue; }
    if (DANGER[op]) found.add(DANGER[op]);
  }
  return [...found];
}

async function main() {
  const { walletClient, account } = requireWallet();

  console.log('\nCompiling HoneypotVault.sol ...');
  const { abi, bytecode } = compileContract('HoneypotVault.sol', 'HoneypotVault');

  console.log('Deploying HoneypotVault as Recipient B ...');
  const hash = await walletClient.deployContract({ abi, bytecode, account });
  console.log(`  tx: ${hash}`);

  const receipt = await waitForSuccess(hash, 'the HoneypotVault deployment');
  const addr = receipt.contractAddress;

  const code = await publicClient.getCode({ address: addr });
  console.log(`\nDeployed at: ${addr}`);
  console.log(`   runtime: ${code.length / 2 - 1} bytes, danger opcodes: ${dangerOpcodes(code).join(', ')}`);
  console.log(`   explorer: ${addressUrl(addr)}`);
  console.log(`\nPut this in your .env:\n   BAD_RECIPIENT="${addr}"\n`);
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

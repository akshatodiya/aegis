// One write, a whole family dead.
//
// The codehash kill-switch blocks by keccak256 of the recipient's runtime code,
// which means it matches an exact artifact and not a "family" in general - a
// recompile of the same source changes solc's metadata trailer and escapes it.
// That is stated plainly in THREAT-MODEL.md, because overclaiming it would be
// worse than the limitation.
//
// But there is a case where it genuinely does kill a family, and it's the case
// that actually shows up in the wild: EIP-1167 minimal proxies. A clone is 45
// bytes of runtime with the implementation address baked into the middle and
// nothing else - no metadata trailer, no compiler fingerprint. Deploy the same
// implementation behind a hundred clones and all hundred have byte-identical
// runtime, so all hundred share one codehash. Blocking it once blocks them all,
// including clones that don't exist yet.
//
// This script deploys real clones of the honeypot on Arc and proves it.
//
//   npm run clone-family        deploy 2 clones and walk the whole beat
//   npm run clone-family -- 3   deploy 3
import { keccak256, formatUnits } from 'viem';
import {
  publicClient, requireWallet, addresses, assertAddress, txUrl,
} from '../src/config.js';
import { compileGuard } from '../src/compile.js';
import { checkBytecode } from '../src/lanes/bytecode.js';
import { recordVerdictOnChain, verdictName } from '../src/guard.js';

// EIP-1167. the first 10 bytes are the constructor (return the 45 bytes that
// follow); the rest is the runtime that delegatecalls to `impl` forever.
function cloneInitCode(impl) {
  return '0x3d602d80600a3d3981f3363d3d373d3d3d363d73'
    + impl.slice(2).toLowerCase()
    + '5af43d82803e903d91602b57fd5bf3';
}

async function main() {
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const impl = assertAddress('BAD_RECIPIENT', addresses.bad);
  const { walletClient, account } = requireWallet();
  const abi = compileGuard().abi;

  // Number('abc') is NaN and Math.max(2, NaN) is NaN, which would silently skip
  // the deploy loop and die later on an undefined address. fail on the argument.
  const arg = process.argv[2];
  if (arg !== undefined && !Number.isInteger(Number(arg))) {
    throw new Error(`clone count must be a whole number, got "${arg}".`);
  }
  const count = Math.max(2, Number(arg || 2));
  const assess = (to) => publicClient.readContract({
    address: guard, abi, functionName: 'assess', args: [to, 1_000_000n],
  });

  console.log(`\nCloning the honeypot ${impl} behind ${count} EIP-1167 proxies\n`);

  const clones = [];
  for (let i = 0; i < count; i++) {
    const hash = await walletClient.sendTransaction({ account, data: cloneInitCode(impl) });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    clones.push(receipt.contractAddress);
    console.log(`  clone ${i + 1}  ${receipt.contractAddress}   ${txUrl(hash)}`);
  }

  // the point: different addresses, identical code, identical codehash
  console.log('\nTheir runtime code:');
  const seen = new Set();
  for (const addr of clones) {
    const code = await publicClient.getCode({ address: addr });
    const ch = keccak256(code);
    seen.add(ch);
    console.log(`  ${addr}`);
    console.log(`    ${code}`);
    console.log(`    codehash ${ch}`);
  }
  console.log(`\n  distinct codehashes across ${clones.length} clones: ${seen.size}`
    + (seen.size === 1 ? '  <- one family, one hash' : '  <- unexpected, they should match'));

  // and the lane names the shape rather than just shrugging at a DELEGATECALL
  const lane = await checkBytecode(clones[0]);
  console.log(`\nBytecode lane on clone 1: ${lane.level} (${lane.score})`);
  console.log(`  ${lane.reason}`);

  console.log('\nGuard verdicts before blocking:');
  for (const addr of clones) {
    const [v, why] = await assess(addr);
    console.log(`  ${addr}  ${verdictName(v)}  (${why})`);
  }

  // one write, derived from clone 1 only
  console.log(`\nBlocking the bytecode, using clone 1 (${clones[0]}) alone:`);
  const res = await recordVerdictOnChain(clones[0]);
  console.log(`  ${res.message}`);

  console.log('\nGuard verdicts after that single write:');
  let blocked = 0;
  for (const addr of clones) {
    const [v, why] = await assess(addr);
    if (verdictName(v) === 'BLOCK') blocked++;
    console.log(`  ${addr}  ${verdictName(v)}  (${why})`);
  }

  const note = res.changed
    ? 'one transaction, and every clone of that implementation is blocked'
    : 'the codehash was already blocked from an earlier run, so these clones were\n  born blocked - which is the same point made more sharply';
  console.log(`\n  ${blocked}/${clones.length} blocked. ${note}.`);
  console.log('  A clone deployed tomorrow is blocked the moment it exists, because');
  console.log('  the guard matched the code, not the address.\n');

  const left = await publicClient.getBalance({ address: account.address });
  console.log(`  agent gas float left: ${formatUnits(left, 18)} USDC\n`);
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

// prints the x402 refusals recorded on-chain in AegisAuditLog.
//
//   npm run audit-log
//
// a read, no key needed, no transaction sent. every line here is something the
// firewall declined to sign, with an explorer link to the write that recorded it
// - which is the point of the contract: on the x402 rail a refusal is otherwise
// just the absence of a signature, and an absence is not something a judge, an
// auditor or an owner can go and look at.
import { formatUnits } from 'viem';
import { readRefusals, auditAddress } from '../src/audit.js';
import { chain, addressUrl } from '../src/config.js';

async function main() {
  const address = auditAddress();
  console.log(`\nAegis audit log ${address} on ${chain.name}`);
  console.log(`  ${addressUrl(address)}\n`);

  const { entries, total, complete } = await readRefusals();

  if (total === 0n) {
    console.log('  Nothing recorded yet. Run npm run x402-demo - beats 2a, 2b and 3 all refuse.');
    console.log('  (An empty log is not evidence that nothing was refused. A compromised');
    console.log('   agent simply never calls this - see the contract header.)\n');
    return;
  }

  for (const e of entries) {
    // the code, where the contract stored one. entries written before refusal
    // codes existed simply don't have one, and are printed as they always were.
    const label = `${e.verdict === 'ASK_HUMAN' ? 'ASK_HUMAN' : 'BLOCK    '}${e.code ? `  ${e.code}` : ''}`;
    console.log(`  #${e.id}  ${label}  ${e.recipient}`);
    console.log(`      ${formatUnits(e.amount, 6)} USDC demanded`);
    console.log(`      ${e.reason}`);
    console.log(`      ${e.url}\n`);
  }

  console.log(`  ${entries.length} shown, ${total} recorded by the contract.`);
  if (!complete) {
    // the contract's own counter is the check on the query: getLogs only covers
    // a window, and a gateway can cap what it returns, so "I found four" and
    // "there are four" are different claims. say which one this is.
    console.log('  Older entries fall outside the block window this reads - the counter above');
    console.log('  is the contract\'s, so the gap is query range, not missing history.');
  }
  console.log();
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

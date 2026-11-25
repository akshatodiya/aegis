// one-time wiring after deploy-guard: approve the guard to pull USDC from the
// treasury, and whitelist this wallet as an agent. run once before guard-good.
import { setupGuard } from '../src/guard.js';

async function main() {
  console.log('\nSetting up AegisGuard ...');
  await setupGuard();
  console.log('Done. Try: npm run guard-good  /  npm run guard-bad\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

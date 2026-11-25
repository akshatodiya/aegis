// verifies AegisGuard on sepolia etherscan.
//
// with ETHERSCAN_API_KEY set it submits the standard-json input over the v2 API
// and polls until it's verified. without a key it just writes the json + args so
// you can upload them on the etherscan UI by hand (no key needed either way).
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { parseUnits, encodeAbiParameters } from 'viem';
import { compileInput } from '../src/compile.js';
import { requireWallet, addresses, assertAddress, chain } from '../src/config.js';

const require = createRequire(import.meta.url);
const solc = require('solc');

const CHAIN_ID = 11155111; // sepolia
const API = 'https://api.etherscan.io/v2/api';

// "0.8.36+commit.8a079791.Emscripten.clang" -> "v0.8.36+commit.8a079791"
function compilerVersion() {
  const m = solc.version().match(/^(\d+\.\d+\.\d+\+commit\.[0-9a-f]+)/);
  if (!m) throw new Error('could not read solc version: ' + solc.version());
  return 'v' + m[1];
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function submit(body, key) {
  const url = `${API}?chainid=${CHAIN_ID}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...body, apikey: key }),
  });
  return res.json();
}

async function main() {
  const { account } = requireWallet();
  // this one really is Sepolia-only: it posts to Etherscan's v2 API with the
  // chain id hardcoded above, while the Arc deployment is verified on arcscan.
  // under the default CHAIN=arc it would otherwise submit the Arc guard address
  // to a chain that has never seen it and fail with an unhelpful API error.
  if (chain.id !== CHAIN_ID) {
    throw new Error(
      `verify-guard targets Sepolia Etherscan (chain ${CHAIN_ID}), but CHAIN is ${chain.name} (${chain.id}).\n` +
      '  The Arc guard is verified on testnet.arcscan.app, not here. Set CHAIN=sepolia to verify that deployment.',
    );
  }

  const usdc = assertAddress('USDC_ADDRESS', addresses.usdc);
  const guard = assertAddress('AEGIS_GUARD', addresses.guard);
  const treasury = account.address;
  const dailyLimit = parseUnits('100', 6); // must match how the guard was deployed

  const stdInput = JSON.stringify(compileInput('AegisGuard.sol'));
  const args = encodeAbiParameters(
    [{ type: 'address' }, { type: 'address' }, { type: 'uint256' }],
    [usdc, treasury, dailyLimit],
  ).slice(2);

  // always drop the files on disk, they're handy regardless
  const outDir = fileURLToPath(new URL('../contracts/out/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  writeFileSync(outDir + 'AegisGuard.standard-input.json', stdInput);

  const key = process.env.ETHERSCAN_API_KEY;
  if (!key) {
    console.log('\nNo ETHERSCAN_API_KEY - wrote the files for manual upload:');
    console.log('  ' + outDir + 'AegisGuard.standard-input.json');
    console.log('  compiler v0.8.36, optimizer on / 200 runs, MIT');
    console.log('  constructor args (no 0x): ' + args + '\n');
    return;
  }

  console.log(`\nSubmitting AegisGuard (${guard}) to Sepolia Etherscan ...`);
  const sent = await submit({
    module: 'contract',
    action: 'verifysourcecode',
    contractaddress: guard,
    sourceCode: stdInput,
    codeformat: 'solidity-standard-json-input',
    contractname: 'AegisGuard.sol:AegisGuard',
    compilerversion: compilerVersion(),
    constructorArguements: args,
    licenseType: 3, // MIT
  }, key);

  if (sent.status !== '1') {
    // already-verified comes back as an error message, treat it as done
    if (String(sent.result).toLowerCase().includes('already verified')) {
      console.log('Already verified.\n');
      return;
    }
    throw new Error('submit failed: ' + sent.result);
  }

  const guid = sent.result;
  console.log('  guid: ' + guid + ', polling ...');

  for (let i = 0; i < 20; i++) {
    await sleep(4000);
    const check = await submit({ module: 'contract', action: 'checkverifystatus', guid }, key);
    const r = String(check.result);
    if (check.status === '1') {
      console.log(`\nVerified: https://sepolia.etherscan.io/address/${guard}#code\n`);
      return;
    }
    if (r.toLowerCase().includes('pending')) { process.stdout.write('.'); continue; }
    if (r.toLowerCase().includes('already verified')) { console.log('\nAlready verified.\n'); return; }
    throw new Error('verification failed: ' + r);
  }
  console.log('\nStill pending - check the address on Etherscan in a minute.\n');
}

main().catch((err) => {
  console.error('\nerror:', err.shortMessage || err.message);
  process.exit(1);
});

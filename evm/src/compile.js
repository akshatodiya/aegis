// compiles a contract from contracts/ with solc and hands back { abi, bytecode }.
// contracts here are small, so we compile on demand rather than committing build
// artifacts that would drift out of sync. also exposes the standard-json input
// (compileInput) so the same bytes can be reused for etherscan verification.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const solc = require('solc');

function sourcePath(file) {
  return fileURLToPath(new URL(`../contracts/${file}`, import.meta.url));
}

export function compileInput(file) {
  const source = readFileSync(sourcePath(file), 'utf8');
  return {
    language: 'Solidity',
    sources: { [file]: { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: {
        '*': { '*': ['abi', 'evm.bytecode.object', 'metadata'] },
      },
    },
  };
}

export function compileContract(file, name) {
  const input = compileInput(file);
  const out = JSON.parse(solc.compile(JSON.stringify(input)));

  // real errors stop us; warnings (e.g. selfdestruct is deprecated) are fine
  const errors = (out.errors || []).filter((e) => e.severity === 'error');
  if (errors.length) {
    throw new Error('solc:\n' + errors.map((e) => e.formattedMessage).join('\n'));
  }

  const c = out.contracts[file][name];
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}

export function compileGuard() {
  return compileContract('AegisGuard.sol', 'AegisGuard');
}

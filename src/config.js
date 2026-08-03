// env + viem clients. defaults to Arc (Circle's stablecoin L1), the chain we're
// building the hackathon MVP on; set CHAIN=sepolia to fall back to the original
// Ethereum testnet deployment.
import 'dotenv/config';
import { createPublicClient, createWalletClient, http, fallback, isAddress, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

// Arc testnet, verified against docs.arc.io. USDC is the native gas token (18
// decimals) AND is exposed as a 6-decimal ERC-20 at the address below - that
// ERC-20 is the USDC the guard actually moves via transferFrom.
export const ARC_USDC = '0x3600000000000000000000000000000000000000';
export const arcTestnet = defineChain({
  id: 5042002,
  name: 'Arc Testnet',
  nativeCurrency: { name: 'USD Coin', symbol: 'USDC', decimals: 18 },
  rpcUrls: { default: { http: ['https://rpc.testnet.arc.network'] } },
  blockExplorers: { default: { name: 'Arcscan', url: 'https://testnet.arcscan.app' } },
  testnet: true,
});

const CHAINS = { arc: arcTestnet, sepolia };
const CHAIN = (process.env.CHAIN || 'arc').toLowerCase();
export const chain = CHAINS[CHAIN] ?? arcTestnet;

const {
  RPC_URL,
  PRIVATE_KEY,
  USDC_ADDRESS,
  GOOD_RECIPIENT,
  BAD_RECIPIENT,
  AEGIS_GUARD,
  AEGIS_AUDIT_LOG,
  X402_WALLET,
  X402_PRIVATE_KEY,
} = process.env;

// the public Arc gateways. the main one rate-limits under a demo's burst of
// requests ("request limit reached"), so when no RPC_URL is pinned we rotate:
// viem's fallback transport moves to the next gateway when one errors.
const ARC_RPCS = [
  'https://rpc.testnet.arc.network',
  'https://rpc.drpc.testnet.arc.network',
  'https://rpc.blockdaemon.testnet.arc.network',
  'https://rpc.quicknode.testnet.arc.network',
];

// an explicit RPC_URL always wins (a dedicated endpoint behaves predictably);
// otherwise Arc gets the gateway rotation, and Sepolia has no default we'd
// want to hardcode, so there it stays required.
const _transport = RPC_URL
  ? http(RPC_URL)
  : chain.id === arcTestnet.id
    ? fallback(ARC_RPCS.map((url) => http(url)))
    : null;
if (!_transport) {
  throw new Error('RPC_URL missing in .env - copy .env.example to .env and fill it in.');
}
// exported so a script that has to build its own wallet (rotate-keys' treasury
// approval, which signs with a key this config deliberately never loads) gets
// the same endpoint and the same gateway rotation as everything else.
export const transport = _transport;

// read-only client, always available
export const publicClient = createPublicClient({
  chain,
  transport,
});

// only build the wallet if a key is present, so balance/bytecode checks
// still run before the key is filled in
let _account = null;
let _walletClient = null;
if (PRIVATE_KEY && PRIVATE_KEY.trim() !== '') {
  const key = PRIVATE_KEY.startsWith('0x') ? PRIVATE_KEY : `0x${PRIVATE_KEY}`;
  _account = privateKeyToAccount(key);
  _walletClient = createWalletClient({
    account: _account,
    chain,
    transport,
  });
}

export const account = _account;
export const walletClient = _walletClient;

// the x402 float wallet's OWN account. deliberately a second key: this wallet
// signs EIP-3009 payment authorizations, so if it were the treasury key, every
// x402 signature would be drawn against the whole treasury and the float
// architecture would be pointless. it only ever signs - it never sends a tx -
// so there's no wallet client for it, just the account.
let _x402Account = null;
if (X402_PRIVATE_KEY && X402_PRIVATE_KEY.trim() !== '') {
  const key = X402_PRIVATE_KEY.startsWith('0x') ? X402_PRIVATE_KEY : `0x${X402_PRIVATE_KEY}`;
  _x402Account = privateKeyToAccount(key);
}
export const x402Account = _x402Account;

// call this before sending anything
export function requireWallet() {
  if (!_walletClient || !_account) {
    throw new Error('PRIVATE_KEY missing in .env - needed to send transactions.');
  }
  return { walletClient: _walletClient, account: _account };
}

export const addresses = {
  // on Arc the USDC ERC-20 iface lives at a known fixed address, so default to it
  // and let .env override; on any other chain it must be set explicitly.
  usdc: USDC_ADDRESS || (chain.id === arcTestnet.id ? ARC_USDC : undefined),
  good: GOOD_RECIPIENT,
  bad: BAD_RECIPIENT,
  guard: AEGIS_GUARD, // the deployed AegisGuard, set after deploy-guard
  // the deployed AegisAuditLog. optional everywhere: with it unset the audit
  // logger turns itself off and every demo runs exactly as before, because this
  // contract records refusals and never authorizes anything.
  auditLog: AEGIS_AUDIT_LOG,
  // the agent's x402 signing wallet - holds only a float, refilled via the guard.
  // separate from the treasury on purpose (see ensureFloat in guard.js). if the
  // key is present we derive the address from it, so the two can never disagree.
  float: _x402Account?.address || X402_WALLET,
};

// the EIP-712 domain of the USDC we sign x402 authorizations against. PINNED,
// not taken from the counterparty's 402 - a server that lies about name/version
// only yields an invalid signature, but we don't let it choose what we sign.
// Verified on-chain: Arc USDC reports name "USDC" / version "2"; Sepolia's
// Circle USDC is "USD Coin" / "2". Override via env if a deployment differs.
export const usdcDomain = {
  name: process.env.USDC_DOMAIN_NAME || (chain.id === arcTestnet.id ? 'USDC' : 'USD Coin'),
  version: process.env.USDC_DOMAIN_VERSION || '2',
};

// Wait for a write and refuse to call a reverted transaction a success.
//
// waitForTransactionReceipt resolves for a transaction that was mined and
// reverted just as happily as for one that worked - status is a field on the
// receipt, not an error. So `await waitForTransactionReceipt(...)` on its own
// reads like a confirmation and is not one, and every place that did it went on
// to print a link and a success message for a write that may not have happened.
//
// This matters most where writes come in ordered sets: rotate-keys authorises a
// new agent before revoking the old one precisely so there is never a moment
// with nobody able to pay, and that ordering only means anything if step one
// failing stops step two. Throwing here is what makes it stop.
// `client` is injectable so the tests can point this at their own anvil rather
// than at whatever chain the env happens to name.
export async function waitForSuccess(hash, what = 'the transaction', client = publicClient) {
  const receipt = await client.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') {
    throw new Error(`${what} was mined but reverted: ${txUrl(hash)}`);
  }
  return receipt;
}

export function assertAddress(label, value) {
  if (!value || !isAddress(value)) {
    throw new Error(`${label} is not a valid address: ${value ?? '(empty)'} - check your .env`);
  }
  return value;
}

// block-explorer links for the active chain (arcscan on Arc, etherscan on
// sepolia) so demo output always points at the right explorer.
const explorer = chain.blockExplorers.default.url;
export function txUrl(hash) {
  return `${explorer}/tx/${hash}`;
}
export function addressUrl(addr) {
  return `${explorer}/address/${addr}`;
}

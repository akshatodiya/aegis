// the x402 rail's receipt drawer - writes refusals to AegisAuditLog.
//
// On the treasury rail a refusal is already a public artifact: guardedPay
// reverts and the failed transaction sits on Arcscan forever. On the x402 rail
// there is nothing to look at. The payment was a signature we declined to
// create, so the refusal is an absence, and an absence is not evidence. This
// module is how that absence gets a receipt.
//
// Three rules it follows, in order of how easy they are to get wrong:
//
//  1. Logging never sits in the refusal path. onRefuse() is synchronous, cannot
//     throw, and returns immediately; the transaction goes out behind it. A
//     firewall whose refusal can be delayed (or broken) by its own bookkeeping
//     is a firewall with a new failure mode, and the refusal already happened -
//     nothing we do here can change it.
//  2. One refusal, one entry. The same error object surfaces through both x402
//     hooks (the signer refuses, the fetch wrapper re-throws), so we dedupe on
//     object identity. Identity, not text: two genuinely separate refusals that
//     read the same are two entries.
//  3. One transaction at a time. These all come from the same key, so a fan-out
//     would race on the nonce; the writes queue behind each other instead.
//
// What this is NOT is an enforcement point, and the contract's own header says
// so at more length. By the time anything here runs, the signature was already
// never created. See THREAT-MODEL.md.
import { isAddress } from 'viem';
import { compileContract } from './compile.js';
import { publicClient, requireWallet, addresses, assertAddress, txUrl } from './config.js';
import { DECISION } from './aegis.js';

const ZERO = '0x0000000000000000000000000000000000000000';
const MAX_UINT256 = (1n << 256n) - 1n;

// keep in step with AegisAuditLog: enum Verdict { Block, AskHuman }
export const AUDIT_VERDICT = { BLOCK: 0, ASK_HUMAN: 1 };
// and with its MAX_REASON_BYTES. over this the contract reverts, so we trim
// before sending rather than discover it on chain.
export const MAX_REASON_BYTES = 256;

// how far back readRefusals looks. same reason as the behavior lane: the public
// Arc gateways reject wide getLogs ranges, so this is a window over recent
// history, not the whole chain.
const WINDOW = 50_000n;

let _abi = null;
export function auditAbi() {
  if (!_abi) _abi = compileContract('AegisAuditLog.sol', 'AegisAuditLog').abi;
  return _abi;
}

export function auditAddress() {
  return assertAddress('AEGIS_AUDIT_LOG', addresses.auditLog);
}

function refusedEvent() {
  return auditAbi().find((item) => item.type === 'event' && item.name === 'Refused');
}

// Fit a reason into what the contract accepts, measured the way the contract
// measures it - in BYTES, not JS string length, which differ the moment anything
// non-ASCII shows up.
//
// This is not politeness. Reason strings quote the wire: "bait-and-switch: X is
// demanding <amount> base units" carries a number the counterparty chose, and
// the amount only had to match /^\d+$/ to get this far, so a hostile 402 can
// make it as long as it likes. Trimming here is what stops a merchant deciding
// how much gas our audit write costs.
export function trimReason(reason) {
  const text = String(reason ?? '').replace(/\s+/g, ' ').trim();
  if (text === '') return 'refused (no reason recorded)';

  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= MAX_REASON_BYTES) return text;

  // cut short of the limit, drop a replacement char if the cut landed inside a
  // multi-byte sequence, and spend the 3 bytes we held back saying it was cut.
  const head = bytes.subarray(0, MAX_REASON_BYTES - 3).toString('utf8').replace(/\uFFFD+$/, '');
  return `${head}...`;
}

// Turn a thrown AegisPaymentRefused into the four fields the contract stores.
// Everything here is hostile-input tolerant on purpose: this runs on the failure
// path, where the values that got us here are exactly the ones that were wrong.
export function refusalEntry(err) {
  const recipient = isAddress(err?.recipient ?? '') ? err.recipient : ZERO;

  // the demanded amount, in USDC base units. a 402 can name a number no uint256
  // can hold, and recording a clamped version of it would be a quieter lie than
  // recording none - the reason string still carries what was actually asked.
  let amount = 0n;
  try {
    const raw = BigInt(err?.amount ?? 0);
    if (raw >= 0n && raw <= MAX_UINT256) amount = raw;
  } catch {
    amount = 0n;
  }

  return {
    recipient,
    amount,
    verdict: err?.verdict === DECISION.ASK_HUMAN ? AUDIT_VERDICT.ASK_HUMAN : AUDIT_VERDICT.BLOCK,
    reason: trimReason(err?.reason ?? err?.message),
  };
}

// the real write. one transaction, waited on, so the caller can print a link.
async function writeRefusal(entry, address) {
  const { walletClient, account } = requireWallet();
  const hash = await walletClient.writeContract({
    address,
    abi: auditAbi(),
    functionName: 'logRefusal',
    args: [entry.recipient, entry.amount, entry.verdict, entry.reason],
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== 'success') throw new Error(`logRefusal reverted (${hash})`);
  return hash;
}

// Build the onRefuse hook both x402 hooks can be handed.
//
//   const audit = createAuditLogger({ log: console.log });
//   createAegisSigner(key, { onRefuse: audit.onRefuse });
//   createAegisX402Fetch({ signer, catalog, onRefuse: audit.onRefuse });
//   ... later ...
//   await audit.flush();
//
// With no AEGIS_AUDIT_LOG in .env the logger is disabled and onRefuse is a no-op,
// so every demo still runs without the contract deployed.
export function createAuditLogger(opts = {}) {
  const {
    address = addresses.auditLog,
    send = null, // injected by tests; otherwise a real transaction
    log = () => {},
    // how many receipts one run will pay for. this is the only way the log can
    // cost something an attacker chooses: refusing is free until it's written,
    // gas on Arc is USDC, and an agent pointed at a hostile service in a loop
    // would otherwise burn its float on receipts for refusals that already
    // worked. past the cap the refusals still happen and still print - they
    // just stop being paid for, and flush() says how many were dropped.
    maxWrites = 25,
  } = opts;

  const enabled = Boolean(send) || (Boolean(address) && isAddress(address));
  const entries = [];
  const seen = new WeakSet();
  let queue = Promise.resolve();
  let written = 0;
  let capNoted = false;

  function onRefuse(err) {
    if (!enabled || !err || typeof err !== 'object') return;
    if (seen.has(err)) return; // rule 2: one refusal, one entry
    seen.add(err);

    const entry = refusalEntry(err);
    entries.push(entry);

    if (written >= maxWrites) {
      // recorded here but not on-chain, and said out loud once. a cap that
      // silently swallowed entries would make a short log look like a quiet one.
      entry.skipped = true;
      if (!capNoted) {
        capNoted = true;
        log(`${maxWrites} receipts written this run - refusals continue, receipts stop (gas bound).`);
      }
      return;
    }
    written += 1;

    // rule 1 and rule 3: hand the write to the queue and return. the catch is
    // attached here, not by the caller, so a failed write can never surface as
    // an unhandled rejection in an agent that is busy refusing a payment.
    queue = queue.then(async () => {
      try {
        entry.hash = await (send ? send(entry) : writeRefusal(entry, address));
        entry.url = txUrl(entry.hash);
        log(`refusal logged on-chain: ${entry.url}`);
      } catch (writeErr) {
        entry.error = writeErr.shortMessage || writeErr.message;
        log(`could not log the refusal on-chain: ${entry.error}`);
      }
    });
  }

  // wait for the queued writes. the refusals themselves already happened - this
  // only decides when we stop caring whether the receipts landed.
  async function flush() {
    await queue;
    return {
      entries,
      logged: entries.filter((e) => e.hash).length,
      failed: entries.filter((e) => e.error).length,
      skipped: entries.filter((e) => e.skipped).length,
    };
  }

  return { enabled, onRefuse, flush, entries };
}

// Read the log back. Returns the entries in the window plus the contract's own
// counter, because those two disagreeing is the interesting case: getLogs is
// bounded by the window and by whatever the gateway decides to return, so
// `complete` is the only way a reader can tell a short log from a short answer.
export async function readRefusals({ window = WINDOW } = {}) {
  const address = auditAddress();
  const [total, latest] = await Promise.all([
    publicClient.readContract({ address, abi: auditAbi(), functionName: 'totalRefusals' }),
    publicClient.getBlockNumber(),
  ]);

  const logs = await publicClient.getLogs({
    address,
    event: refusedEvent(),
    fromBlock: latest > window ? latest - window : 0n,
    toBlock: 'latest',
  });

  const entries = logs.map((entry) => ({
    id: entry.args.id,
    reporter: entry.args.reporter,
    recipient: entry.args.recipient,
    amount: entry.args.amount,
    verdict: Number(entry.args.verdict) === AUDIT_VERDICT.ASK_HUMAN ? DECISION.ASK_HUMAN : DECISION.BLOCK,
    reason: entry.args.reason,
    hash: entry.transactionHash,
    url: txUrl(entry.transactionHash),
    block: entry.blockNumber,
  }));

  return { entries, total, complete: BigInt(entries.length) === total };
}

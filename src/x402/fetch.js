// the Aegis x402 fetch wrapper - hook (A), where the decision gets made.
//
// A normal x402 client (wrapFetchWithPayment) sees a 402, signs a payment and
// retries, no questions asked. Aegis slots in between: on a 402 it reads the
// PaymentRequirements and, BEFORE anything is signed, asks the questions that
// need context the signer doesn't have -
//   - is payTo a service we actually know (catalog / marketplace registry)?
//   - is the demanded amount within that service's posted price (bait-and-switch)?
// Only then does it hand the payment to the Aegis signer (hook B), which
// re-checks the hard invariants and runs the bytecode/denylist verdict on payTo
// before it will produce the EIP-3009 signature. Two call sites, one policy.
//
// We build the exact-scheme payment ourselves rather than lean on an SDK, so the
// demo can't drift from whatever facilitator version is live, and so every field
// we sign is one we chose. Amounts stay in USDC base units end to end. A hostile
// or malformed 402 must always fail closed with AegisPaymentRefused, never crash.
import { randomBytes } from 'node:crypto';
import { AegisPaymentRefused } from './signer.js';
import { DECISION } from '../aegis.js';
import { chain, addresses, assertAddress, usdcDomain } from '../config.js';

const MAX_TTL_SECONDS = 120;

// EIP-3009 typed-data shape the "exact" EVM scheme signs.
const TRANSFER_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
};

const b64encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64');
const b64decode = (s) => JSON.parse(Buffer.from(s, 'base64').toString('utf8'));

// read the PaymentRequirements out of a 402, tolerating both the header-carried
// (base64) form and a JSON body, and both the single-object and { accepts: [...] }
// shapes. also work out which x402 version we're talking to so the reply matches.
async function parseRequirements(res) {
  const header =
    res.headers.get('payment-required') || res.headers.get('x-payment-required');
  let doc = null;
  let fromHeader = false;
  if (header) {
    try { doc = b64decode(header); fromHeader = true; } catch { doc = null; }
  }
  if (!doc) {
    doc = await res.clone().json().catch(() => null);
  }
  if (!doc || typeof doc !== 'object') return { options: [], version: 2 };

  const options = Array.isArray(doc) ? doc : Array.isArray(doc.accepts) ? doc.accepts : [doc];
  // v2 carries requirements in the header and uses `amount`; v1 is a JSON body
  // with `x402Version:1` / `maxAmountRequired`. detect so we reply in kind.
  let version = 2;
  if (Number(doc.x402Version) === 1) version = 1;
  else if (!fromHeader && options.some((o) => o && o.maxAmountRequired != null && o.amount == null)) version = 1;
  return { options, version };
}

// chainId can arrive as "eip155:5042002" or a bare number. anchor the match so
// "solana:5042002" or "tron5042002" don't parse as our chain.
function networkChainId(network) {
  if (typeof network === 'number') return network;
  const m = String(network ?? '').match(/^(?:eip155:)?(\d+)$/);
  return m ? Number(m[1]) : NaN;
}

// normalize one requirement, REJECTING malformed ones (throws) so a hostile
// field can't slip through or crash us. callers skip options that throw.
function normalize(opt) {
  const amountStr = String(opt.amount ?? opt.maxAmountRequired ?? '');
  if (!/^\d+$/.test(amountStr) || BigInt(amountStr) === 0n) {
    throw new Error(`bad amount: ${JSON.stringify(opt.amount ?? opt.maxAmountRequired)}`);
  }
  const timeout = Number(opt.maxTimeoutSeconds ?? 60);
  if (!Number.isFinite(timeout) || timeout < 0) {
    throw new Error(`bad maxTimeoutSeconds: ${JSON.stringify(opt.maxTimeoutSeconds)}`);
  }
  return {
    scheme: opt.scheme,
    network: opt.network,
    chainId: networkChainId(opt.network),
    asset: opt.asset,
    payTo: opt.payTo,
    amount: BigInt(amountStr),
    maxTimeoutSeconds: timeout,
  };
}

// pick the requirement we can actually pay: the exact scheme, on our chain, in
// our USDC. malformed options are skipped, not fatal, so a poison option can't
// hide a valid one later in the array.
function selectOption(options, { chainId, usdc }) {
  for (const raw of options) {
    let o;
    try { o = normalize(raw); } catch { continue; }
    if (
      o.scheme === 'exact' &&
      o.chainId === chainId &&
      String(o.asset).toLowerCase() === usdc.toLowerCase()
    ) {
      return o;
    }
  }
  return null;
}

export function createAegisX402Fetch(opts = {}) {
  const {
    signer,
    catalog,
    fetchImpl = fetch,
    usdc = assertAddress('USDC_ADDRESS', addresses.usdc),
    chainId = chain.id,
    maxTtl = MAX_TTL_SECONDS,
    domain = usdcDomain, // pinned name/version, not taken from the server
    now = () => Math.floor(Date.now() / 1000),
    log = () => {},
    // per-payment spend cap on the x402 rail, in base units (null = no cap).
    // this cap is CLIENT-side policy: an x402 payment settles off the mempool,
    // so the guard's on-chain dailyLimit can only meter the float refill - it
    // cannot pause a single payment and ask anyone anything. this is where the
    // ASK_HUMAN lane lives for x402: over the cap, we stop and put a human in
    // the loop instead of silently paying or silently dropping.
    maxPerPayment = null,
    // async ({ service, amount, cap }) => boolean. no handler wired = nobody to
    // ask = fail closed and refuse. the demo passes a readline y/N prompt here.
    askHuman = null,
    // fired on every refusal, same shape as the signer's hook. this rail refuses
    // in two places - here, on context the signer cannot see, and in the signer
    // itself - so a receipt drawer wired to only one of them would miss half the
    // refusals. must not throw and must not block (src/audit.js).
    onRefuse = null,
  } = opts;

  if (!signer) throw new Error('createAegisX402Fetch needs an Aegis signer');
  if (!catalog) throw new Error('createAegisX402Fetch needs a service catalog');

  async function pay(option, version) {
    const ts = now();
    const authorization = {
      from: signer.address,
      to: option.payTo,
      value: option.amount.toString(),
      validAfter: (ts - 6).toString(), // small backdate for clock skew
      validBefore: (ts + Math.min(option.maxTimeoutSeconds, maxTtl)).toString(),
      nonce: '0x' + randomBytes(32).toString('hex'),
    };

    // the signer re-enforces asset==USDC / chain / ttl and runs aegisCheck(payTo).
    // if it refuses, it throws AegisPaymentRefused and no signature exists.
    const signature = await signer.signTypedData({
      domain: { name: domain.name, version: domain.version, chainId, verifyingContract: option.asset },
      types: TRANSFER_TYPES,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: authorization.from,
        to: authorization.to,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
        nonce: authorization.nonce,
      },
    });

    const payload = b64encode({
      x402Version: version,
      scheme: 'exact',
      network: option.network,
      payload: { signature, authorization },
    });
    return payload;
  }

  async function attempt(url, init) {
    const res = await fetchImpl(url, init);
    if (res.status !== 402) return res;

    log(`402 from ${url} - screening the payment demand...`);
    const { options, version } = await parseRequirements(res);
    const option = selectOption(options, { chainId, usdc });
    if (!option) {
      throw new AegisPaymentRefused(
        `no acceptable payment option (need exact scheme on chain ${chainId} in USDC ${usdc}).`,
      );
    }

    // from here on we know who wants paying and how much, so every refusal can
    // say so - that pair is what makes an audit entry worth reading.
    const about = { recipient: option.payTo, amount: option.amount };

    // (A) context checks the signer can't do - is this a known service at a sane price?
    const service = catalog.lookup(option.payTo);
    if (!service) {
      throw new AegisPaymentRefused(
        `payTo ${option.payTo} is not a service in the catalog - refusing to pay an unknown recipient.`,
        DECISION.BLOCK, about,
      );
    }
    if (option.amount > service.maxPrice) {
      throw new AegisPaymentRefused(
        `bait-and-switch: "${service.name}" is demanding ${option.amount} base units, over its posted ${service.maxPrice}.`,
        DECISION.BLOCK, about,
      );
    }

    // the price is honest but big: over the per-payment cap we don't decide
    // alone - a human approves it or it doesn't happen. note the signer will
    // STILL run its own checks after a yes; approval here doesn't bypass hook B.
    if (maxPerPayment != null && option.amount > maxPerPayment) {
      log(`  "${service.name}" costs ${option.amount} base units, over the ${maxPerPayment} per-payment cap - asking a human.`);
      const approved = askHuman
        ? await askHuman({ service, amount: option.amount, cap: maxPerPayment })
        : false;
      if (!approved) {
        throw new AegisPaymentRefused(
          askHuman
            ? `human declined the over-cap payment (${option.amount} > cap ${maxPerPayment} base units).`
            : `payment of ${option.amount} base units exceeds the per-payment cap ${maxPerPayment} and no human is wired in to approve it.`,
          DECISION.ASK_HUMAN, about,
        );
      }
      log('  human approved the over-cap payment.');
    }

    log(`  known service "${service.name}", ${option.amount} <= posted ${service.maxPrice}. signing...`);

    // (B) sign through the guard, then replay the request with the payment. one
    // header, matching the version the server spoke.
    const paymentHeader = await pay(option, version);
    const headers = new Headers(init.headers || {});
    headers.set(version === 1 ? 'X-PAYMENT' : 'PAYMENT-SIGNATURE', paymentHeader);
    log('  payment signed and attached, retrying request.');
    return fetchImpl(url, { ...init, headers });
  }

  // one place to notice a refusal, whichever check raised it - including the
  // signer's, which reaches here by throwing back through pay(). a refusal that
  // trips both hooks is still ONE refusal, and the audit logger dedupes on the
  // error object's identity to keep it that way.
  return async function aegisFetch(url, init = {}) {
    try {
      return await attempt(url, init);
    } catch (err) {
      if (err instanceof AegisPaymentRefused && onRefuse) onRefuse(err);
      throw err;
    }
  };
}

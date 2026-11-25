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
import { REFUSAL } from '../refusals.js';
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

// how much of the seller's copy we're willing to carry, in characters.
const LIMITS = { url: 200, description: 160, mimeType: 64 };

// Clean one string the counterparty wrote.
//
// This is the only text in the whole rail that a seller composes and a human
// then reads while deciding whether to release money, so it is handled as
// hostile input rather than as a label:
//   - control bytes go. an ANSI escape can repaint a terminal and a carriage
//     return can overwrite the line above it, which is enough to forge the
//     prompt itself. they become spaces rather than vanishing, so "a<ESC>b"
//     can't quietly close up into a word nobody sent.
//   - the format characters go, matched by Unicode property rather than by a
//     list. the list this started as covered the ones everybody knows and
//     missed U+061C, which is a bidi control like the others, and the whole
//     U+E0000 tag block, which is invisible in every terminal and is what
//     ascii-smuggling payloads are written in. an enumeration of hostile
//     characters is a promise to keep up with Unicode, and \p{Cf} is the same
//     promise kept by the runtime instead. the blank characters that are
//     letters rather than format (the hangul fillers) are named separately,
//     because there is no property that means "renders as nothing".
//   - whitespace collapses, so the seller gets one line and cannot lay out
//     something that looks like our own output underneath it.
//   - and it's capped, because the party asking for money doesn't get to decide
//     how much of the screen the question occupies.
// What survives is quoted and attributed when it's shown. This defangs the
// formatting, not the meaning: a description can still be an outright lie, and
// nothing here is treated as evidence of anything. See THREAT-MODEL.md.
function cleanText(value, limit) {
  if (typeof value !== 'string') return null;
  const flat = value
    .replace(/\p{Cc}/gu, ' ')
    .replace(/[\p{Cf}\p{Zl}\p{Zp}\u034f\u115f\u1160\u3164\uffa0]/gu, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!flat) return null;
  // slice by code point, so a cap can't land in the middle of a surrogate pair
  const chars = Array.from(flat);
  return chars.length <= limit ? flat : `${chars.slice(0, limit - 3).join('')}...`;
}

// What the seller says it is selling. x402 carries this two ways and we take
// either: in v1 `resource` is the url string with `description` and `mimeType`
// beside it on the requirement, and in v2 it's a ResourceInfo object
// { url, description, mimeType } hung off the PaymentRequired document rather
// than off any single requirement. Returns null when there's nothing to show,
// and never throws - a mangled description is not a reason to refuse a payment
// whose terms are fine, it's just a description we won't repeat.
function resourceInfo(source) {
  if (!source || typeof source !== 'object') return null;
  const raw = source.resource;
  const obj = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const url = cleanText(typeof raw === 'string' ? raw : obj.url, LIMITS.url);
  const description = cleanText(obj.description ?? source.description, LIMITS.description);
  const mimeType = cleanText(obj.mimeType ?? source.mimeType, LIMITS.mimeType);
  return url || description || mimeType ? { url, description, mimeType } : null;
}

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
  if (!doc || typeof doc !== 'object') return { options: [], version: 2, resource: null };

  const options = Array.isArray(doc) ? doc : Array.isArray(doc.accepts) ? doc.accepts : [doc];
  // v2 carries requirements in the header and uses `amount`; v1 is a JSON body
  // with `x402Version:1` / `maxAmountRequired`. detect so we reply in kind.
  let version = 2;
  if (Number(doc.x402Version) === 1) version = 1;
  else if (!fromHeader && options.some((o) => o && o.maxAmountRequired != null && o.amount == null)) version = 1;
  // the v2 ResourceInfo describes the whole document, so it's read here rather
  // than per requirement. v1's lives on each requirement; normalize() takes that.
  return { options, version, resource: resourceInfo(doc) };
}

// what the agent actually asked for, as a string. fetch takes a url, a URL or a
// Request, and only the last of those hides the address behind a property.
function href(url) {
  if (typeof url === 'string') return url;
  return typeof url?.url === 'string' ? url.url : String(url);
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
    // decoration, not terms: it is shown to a human, never compared against
    // anything and never signed. cleaned on the way in all the same.
    resource: resourceInfo(opt),
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
    // async ({ service, amount, cap, resource, requestUrl }) => true | false | null.
    // no handler wired = nobody to ask = fail closed and refuse. the demo passes
    // a readline y/N prompt here.
    //
    // Only `true` approves. Anything else does not, and the three outcomes are
    // told apart because they are not the same event: `false` is a person who
    // said no, `null` (or undefined) is a handler saying nobody was there to
    // ask - an unattended run, a closed tty - and a throw is the prompt itself
    // breaking. They refuse identically and they carry different codes, because
    // "retry when someone is around" is only sound advice for one of them.
    //
    // `service` is what our own catalog says it is; `resource` is what the
    // seller says it is selling, cleaned by cleanText and possibly null. Both
    // are handed over precisely because they can disagree, and the human is the
    // one who should get to notice that. A handler that shows them must keep
    // them apart - the party asking for the money doesn't get to narrate the
    // question. `requestUrl` is the url the agent actually asked for, which is
    // not necessarily the url the 402 claims to be describing.
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
    const { options, version, resource: offered } = await parseRequirements(res);
    const option = selectOption(options, { chainId, usdc });
    if (!option) {
      // no recipient and no amount to report - nothing in `accepts` was payable,
      // so there is no `about` yet. the document still said what it was selling,
      // though, and that is the one refusal where a reader most wants it: "we
      // could not pay for this" reads very differently when you can see what
      // "this" was. it is the same cleaned, quoted, never-compared string as
      // everywhere else.
      throw new AegisPaymentRefused(
        `no acceptable payment option (need exact scheme on chain ${chainId} in USDC ${usdc}).`,
        DECISION.BLOCK, { resource: offered, code: REFUSAL.NO_PAYABLE_OPTION },
      );
    }

    // the requirement's own ResourceInfo (v1) if it has one, else the
    // document's (v2). the specific one wins; either may be missing entirely.
    const resource = option.resource ?? offered;

    // from here on we know who wants paying and how much, so every refusal can
    // say so - that pair is what makes an audit entry worth reading. the
    // resource rides along for whoever prints the refusal; it is deliberately
    // NOT folded into the reason string, because reasons get written on-chain
    // (src/audit.js) and the seller does not get to choose what our receipts say.
    const about = { recipient: option.payTo, amount: option.amount, resource };

    // (A) context checks the signer can't do - is this a known service at a sane price?
    const service = catalog.lookup(option.payTo);
    if (!service) {
      throw new AegisPaymentRefused(
        `payTo ${option.payTo} is not a service in the catalog - refusing to pay an unknown recipient.`,
        DECISION.BLOCK, { ...about, code: REFUSAL.UNKNOWN_SERVICE },
      );
    }
    if (option.amount > service.maxPrice) {
      throw new AegisPaymentRefused(
        `bait-and-switch: "${service.name}" is demanding ${option.amount} base units, over its posted ${service.maxPrice}.`,
        DECISION.BLOCK, { ...about, code: REFUSAL.OVER_POSTED_PRICE },
      );
    }

    // the price is honest but big: over the per-payment cap we don't decide
    // alone - a human approves it or it doesn't happen. note the signer will
    // STILL run its own checks after a yes; approval here doesn't bypass hook B.
    if (maxPerPayment != null && option.amount > maxPerPayment) {
      log(`  "${service.name}" costs ${option.amount} base units, over the ${maxPerPayment} per-payment cap - asking a human.`);
      let answer = null;
      let promptFailed = null;
      if (askHuman) {
        try {
          answer = await askHuman({
            service,
            amount: option.amount,
            cap: maxPerPayment,
            resource,
            requestUrl: href(url),
          });
        } catch (err) {
          // a prompt that breaks is not a yes. it also isn't nothing: let the
          // throw escape as-is and this stops being an AegisPaymentRefused, so
          // onRefuse never fires and a refusal that really happened leaves no
          // receipt. name it and fail closed.
          promptFailed = err?.shortMessage || err?.message || String(err);
        }
      }
      if (answer !== true) {
        // one condition, several different things to do about it, so several
        // codes: "nobody was there" is worth retrying once someone is, and "a
        // person said no" is emphatically not.
        const overCap = `${option.amount} > cap ${maxPerPayment} base units`;
        const [reason, code] = promptFailed
          ? [`the over-cap approval prompt failed (${promptFailed}) - nobody answered, so this is a no.`,
            REFUSAL.APPROVER_FAILED]
          : !askHuman
            ? [`payment of ${option.amount} base units exceeds the per-payment cap ${maxPerPayment} and no human is wired in to approve it.`,
              REFUSAL.NO_APPROVER]
            : answer == null
              ? [`nobody was available to approve the over-cap payment (${overCap}).`,
                REFUSAL.NO_APPROVER]
              : [`human declined the over-cap payment (${overCap}).`,
                REFUSAL.HUMAN_DECLINED];
        throw new AegisPaymentRefused(reason, DECISION.ASK_HUMAN, { ...about, code });
      }
      log('  human approved the over-cap payment.');
    }

    log(`  known service "${service.name}", ${option.amount} <= posted ${service.maxPrice}. signing...`);

    // (B) sign through the guard, then replay the request with the payment. one
    // header, matching the version the server spoke.
    //
    // a refusal raised in there is about this same payment, but the signer is
    // deliberately ignorant of the 402 - it re-derives everything from the
    // authorization it was handed - so it cannot say what was being sold. that
    // one field is filled in here, where we do know, and only if it's empty.
    // the reason, the verdict and the amount are the signer's own and are left
    // exactly as it wrote them.
    let paymentHeader;
    try {
      paymentHeader = await pay(option, version);
    } catch (err) {
      if (err instanceof AegisPaymentRefused && err.resource == null) err.resource = resource;
      throw err;
    }
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

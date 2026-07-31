// The Aegis x402 signer - the enforcement chokepoint on the x402 rail.
//
// An x402 "exact" payment is not a transaction the agent broadcasts. It is an
// EIP-3009 TransferWithAuthorization signed with signTypedData; a facilitator
// later calls transferWithAuthorization() on USDC and moves the money. That
// means the payment NEVER passes through AegisGuard.guardedPay - the on-chain
// firewall can't see it. On this rail the irreversible act is *creating the
// signature*, so that is where Aegis has to stand.
//
// This wraps a viem account into a restricted signer the agent is handed instead
// of the raw key. It is a chokepoint only if it exposes NOTHING that can produce
// a fund-moving signature outside policy, so we deny by default:
//   - raw digest signing (sign), raw tx signing (signTransaction) and 7702
//     delegation (signAuthorization) are disabled outright - each is a total
//     bypass otherwise (sign any digest = forge any payment).
//   - signTypedData is gated: any EIP-3009 payment must clear policy, and any
//     OTHER typed data against our USDC (e.g. an EIP-2612 Permit granting an
//     infinite allowance) is refused too - a Permit drains just as well.
//   - generic typed data on other domains (logins, etc.) passes through.
//
// This bounds a prompt-injected agent, which can only act through the tools it's
// given. It does NOT stop a fully compromised process that reads the key from
// memory - that is what the out-of-process signer and the on-chain float cap are
// for. We don't claim otherwise.
import { erc20Abi } from 'viem';
import { aegisCheck, DECISION } from '../aegis.js';
import { chain, addresses, assertAddress, publicClient } from '../config.js';

// EIP-3009 primary types that move value - each must clear policy.
const PAYMENT_TYPES = new Set(['TransferWithAuthorization', 'ReceiveWithAuthorization']);
// only burns a nonce (cancels a prior authorization); safe to allow unguarded.
const SAFE_TOKEN_TYPES = new Set(['CancelAuthorization']);

// absolute cap on how far in the future a signed authorization may be valid.
// PaymentRequirements carry a maxTimeoutSeconds, but we don't trust the server to
// keep it small - a long-lived signature is a payment someone can settle weeks
// later, after the context that justified it is gone. honor the smaller of the two.
const MAX_TTL_SECONDS = 120;

export class AegisPaymentRefused extends Error {
  constructor(reason, verdict = DECISION.BLOCK, about = {}) {
    super(`Aegis refused to sign this x402 payment: ${reason}`);
    this.name = 'AegisPaymentRefused';
    this.verdict = verdict;
    this.reason = reason;
    // who we declined to pay and how much, in USDC base units, when we got far
    // enough to know. null when we didn't: a malformed authorization or a 402
    // with no payable option is refused before anyone is named, and the audit
    // log records that as the zero address rather than inventing a recipient.
    this.recipient = about.recipient ?? null;
    this.amount = about.amount ?? null;
    // what the seller said it was selling, cleaned, when the refusal happened
    // somewhere that had it (the fetch wrapper does; this signer never sees the
    // 402 at all). here so a caller printing the refusal can say what was on
    // offer. it is NOT part of `reason`, and the audit log only records reason -
    // seller-written prose doesn't get to become our on-chain receipt.
    this.resource = about.resource ?? null;
  }
}

// value is USDC base units (6 decimals on the ERC-20 iface). aegisCheck's
// behavior lane thinks in whole USDC, so convert at this edge and keep every
// on-the-wire number in base units.
function baseUnitsToUsdc(value) {
  return Number(value) / 1e6;
}

// parse a numeric field, turning garbage into a REFUSAL, never a raw throw -
// a hostile 402 must fail closed, not crash the agent.
function safeBig(x, field) {
  try {
    return BigInt(x);
  } catch {
    throw new AegisPaymentRefused(`malformed ${field} in the authorization.`);
  }
}

function readAuthorization(message) {
  return {
    to: message.to,
    value: safeBig(message.value, 'value'),
    validAfter: safeBig(message.validAfter ?? 0, 'validAfter'),
    validBefore: safeBig(message.validBefore ?? 0, 'validBefore'),
    nonce: message.nonce,
  };
}

// the guard that runs before we sign an EIP-3009 authorization.
async function assertPaymentAllowed(
  { domain, message },
  { usdc, chainId, maxTtl, check, now, balanceOf, from },
) {
  const auth = readAuthorization(message);
  // what every refusal below is about, so the receipt says who and how much
  // rather than just why. see AegisPaymentRefused.
  const about = { recipient: auth.to, amount: auth.value };

  // --- invariant 1: the asset. a hostile 402 can name any contract "USDC" and
  // have us sign EIP-712 against it. refuse unless the verifyingContract is the
  // exact USDC we guard. this is the single most important line here.
  const signedAsset = String(domain?.verifyingContract || '').toLowerCase();
  if (signedAsset !== usdc.toLowerCase()) {
    throw new AegisPaymentRefused(
      `authorization is against ${domain?.verifyingContract}, not the canonical USDC ${usdc}.`,
      DECISION.BLOCK, about,
    );
  }

  // --- invariant 2: the chain.
  if (Number(domain?.chainId) !== chainId) {
    throw new AegisPaymentRefused(
      `authorization is for chainId ${domain?.chainId}, not our chain ${chainId}.`,
      DECISION.BLOCK, about,
    );
  }

  // --- invariant 3: freshness. require now < validBefore <= now + cap. a
  // long-lived (or already-expired) authorization is refused outright.
  if (!(auth.validBefore > BigInt(now) && auth.validBefore <= BigInt(now + maxTtl))) {
    throw new AegisPaymentRefused(
      `authorization validBefore ${auth.validBefore} is outside the allowed window (now ${now}, cap ${maxTtl}s).`,
      DECISION.BLOCK, about,
    );
  }
  // validAfter matters too: an authorization that only becomes valid later is
  // one we're signing blind, since the policy we checked it against is today's.
  // our own caller always backdates it, but this signer is the chokepoint - it
  // has to hold for callers that aren't ours.
  if (auth.validAfter >= auth.validBefore) {
    throw new AegisPaymentRefused(
      `authorization validAfter ${auth.validAfter} is not before validBefore ${auth.validBefore}.`,
      DECISION.BLOCK, about,
    );
  }
  if (auth.value <= 0n) {
    throw new AegisPaymentRefused('authorization has a non-positive value.', DECISION.BLOCK, about);
  }

  // don't sign a cheque the wallet can't cash. an authorization for more than
  // the float holds can't settle today, so signing it is pure downside: the
  // signature stays valid until validBefore, and settles the moment someone
  // tops the wallet up. a human approving an over-cap payment approves the
  // AMOUNT, not "and also whatever the balance does next."
  if (from && balanceOf) {
    const held = await balanceOf(from);
    if (auth.value > held) {
      throw new AegisPaymentRefused(
        `authorization is for ${auth.value} base units but the wallet holds ${held} - ` +
        'refusing to leave a signature that settles as soon as it is topped up.',
        DECISION.BLOCK, about,
      );
    }
  }

  // --- the policy verdict: run the same firewall on the payTo.
  const verdict = await check(auth.to, baseUnitsToUsdc(auth.value));
  if (verdict.decision !== DECISION.PAY) {
    throw new AegisPaymentRefused(
      `verdict ${verdict.decision} on payTo ${auth.to}` +
        (verdict.reasons?.length ? ` - ${verdict.reasons[0]}` : ''),
      verdict.decision, about,
    );
  }

  return { auth, verdict };
}

// wrap a viem account into an Aegis-guarded signer.
export function createAegisSigner(account, opts = {}) {
  const {
    usdc = assertAddress('USDC_ADDRESS', addresses.usdc),
    chainId = chain.id,
    maxTtl = MAX_TTL_SECONDS,
    check = (to, amount) => aegisCheck(to, amount),
    // fired on every refusal this signer raises. the CLI uses it to print them;
    // the audit logger uses it to write them on-chain (src/audit.js). it must
    // not throw and must not block - a refusal is not the place to add a new
    // way to fail.
    onRefuse = null,
    now = () => Math.floor(Date.now() / 1000),
    // the wallet's own USDC balance. defaults to reading it on-chain so the
    // "won't sign what it can't settle" rule holds unless a caller deliberately
    // opts out (pass null); offline tests inject a stub instead of a node.
    balanceOf = (who) => publicClient.readContract({
      address: usdc, abi: erc20Abi, functionName: 'balanceOf', args: [who],
    }),
  } = opts;

  const usdcLower = usdc.toLowerCase();

  async function signTypedData(params) {
    const primaryType = params?.primaryType;
    const onGuardedToken = String(params?.domain?.verifyingContract || '').toLowerCase() === usdcLower;

    try {
      if (PAYMENT_TYPES.has(primaryType)) {
        // any EIP-3009 payment, on any asset - assertPaymentAllowed refuses
        // unless it's our USDC, on our chain, fresh, positive, and PAY.
        await assertPaymentAllowed(params, {
          usdc, chainId, maxTtl, check, now: now(), balanceOf, from: account.address,
        });
      } else if (onGuardedToken && !SAFE_TOKEN_TYPES.has(primaryType)) {
        // non-payment typed data on OUR token = a fund-moving primitive we don't
        // model (Permit / approve-by-sig / anything new). refuse it.
        throw new AegisPaymentRefused(
          `signing '${primaryType}' typed-data on the guarded USDC is disabled (fund-moving primitive).`,
        );
      }
    } catch (err) {
      if (err instanceof AegisPaymentRefused && onRefuse) onRefuse(err);
      throw err;
    }
    // payment cleared, or it's generic typed data on some other domain.
    return account.signTypedData(params);
  }

  const deny = (what) => () => {
    const err = new AegisPaymentRefused(`${what} is disabled on the Aegis signer.`);
    if (onRefuse) onRefuse(err);
    throw err;
  };

  // explicit surface: expose only what an x402 EVM signer needs, and nothing
  // that can forge a signature. do NOT spread the account - that would re-expose
  // sign / signTransaction / signAuthorization as one-call bypasses.
  return {
    address: account.address,
    publicKey: account.publicKey,
    type: account.type,
    source: 'aegis',
    signTypedData,
    // EIP-191 personal_sign can't collide with an EIP-712 payment digest, so it's
    // safe to keep for logins / SIWE.
    signMessage: (args) => account.signMessage(args),
    sign: deny('raw digest signing (sign)'),
    signTransaction: deny('raw transaction signing (signTransaction)'),
    signAuthorization: deny('EIP-7702 delegation (signAuthorization)'),
  };
}

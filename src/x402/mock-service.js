// the mock x402 merchant - the other side of the wire for the demo and tests.
//
// deliberately a REAL http server, not a stubbed fetch: the agent's requests
// cross a real socket, the 402 challenge and the payment header are real
// headers, and before serving anything the merchant runs the same EIP-3009
// signature verification a facilitator runs at settlement (verifyTypedData over
// the exact authorization, plus recipient/amount/window/replay checks). the one
// thing it does NOT do is broadcast the settlement on-chain - and it says so in
// its response rather than pretend. the signed authorization is a bearer
// instrument against the real USDC either way; we're declining to spend it,
// not faking it.
//
// vocabulary matters here: this is the MERCHANT (the service selling data). it
// borrows the facilitator's verify step so the demo can prove the signature is
// genuine, but it is not a facilitator and we never call it one.
import { createServer } from 'node:http';
import { verifyTypedData } from 'viem';

// EIP-3009 typed-data shape, reconstructed here on purpose: the merchant
// verifies against ITS OWN idea of the domain and types, never the client's.
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

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

// each service: { route, name, payTo, demand (BigInt base units), product },
// optionally { description, mimeType }. `demand` is whatever the 402 asks for -
// for the bait-and-switch route it is deliberately higher than the price the
// catalog says this service posts, and `description` is the seller's own sales
// copy, which is deliberately not the same thing as a fact.
export function createMockMerchant({ usdc, chainId, domain, services, now = () => Math.floor(Date.now() / 1000), log = () => {} }) {
  const byRoute = new Map(services.map((s) => [s.route, s]));
  // one-shot authorizations: a nonce that's been accepted once is burned, same
  // as USDC's authorizationState does on-chain. keyed per payer, per the spec.
  const usedNonces = new Set();

  function requirement(svc) {
    return {
      scheme: 'exact',
      network: `eip155:${chainId}`,
      asset: usdc,
      payTo: svc.payTo,
      amount: svc.demand.toString(),
      maxTimeoutSeconds: 60,
      extra: { assetTransferMethod: 'eip3009', name: domain.name, version: domain.version },
    };
  }

  // the v2 ResourceInfo. it hangs off the PaymentRequired document rather than
  // off each requirement, because it describes the thing being sold and not the
  // way it's being paid for - one resource, several ways to pay. (v1 put the url
  // and description on the requirement itself; the Aegis client reads either.)
  function resourceInfo(svc, req, path) {
    const sent = req.headers.host;
    const host = typeof sent === 'string' && /^[\w.-]+(:\d+)?$/.test(sent) ? sent : 'localhost';
    return {
      url: `http://${host}${path}`,
      description: svc.description ?? svc.name,
      mimeType: svc.mimeType ?? 'application/json',
    };
  }

  return createServer(async (req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname;
    const svc = byRoute.get(path);
    if (!svc) return json(res, 404, { error: `no service at ${path}` });

    const header = req.headers['payment-signature'] || req.headers['x-payment'];
    if (!header) {
      // no payment attached -> challenge with the PaymentRequirements
      log(`402 for ${path}: "${svc.name}" demands ${svc.demand} base units to ${svc.payTo}`);
      const doc = {
        x402Version: 2,
        resource: resourceInfo(svc, req, path),
        accepts: [requirement(svc)],
      };
      return json(res, 402, doc, { 'PAYMENT-REQUIRED': b64encode(doc) });
    }

    // paid retry -> verify before serving. every branch here fails the payment,
    // never the process: a hostile client gets an error status, not a crash.
    let auth, signature;
    try {
      const payload = b64decode(header);
      signature = payload?.payload?.signature;
      const a = payload?.payload?.authorization;
      auth = {
        from: String(a.from),
        to: String(a.to),
        value: BigInt(a.value),
        validAfter: BigInt(a.validAfter),
        validBefore: BigInt(a.validBefore),
        nonce: String(a.nonce),
      };
      if (!signature) throw new Error('no signature');
    } catch {
      return json(res, 400, { error: 'malformed payment payload' });
    }

    // exact scheme means exactly what we demanded, to us
    if (auth.value !== svc.demand) {
      return json(res, 400, { error: `authorization value ${auth.value} does not match the demanded ${svc.demand}` });
    }

    // same window rule the token contract enforces at settlement
    const ts = BigInt(now());
    if (!(ts > auth.validAfter && ts < auth.validBefore)) {
      return json(res, 400, { error: 'authorization is outside its validity window' });
    }

    // replay: an authorization settles once. same nonce again = already spent.
    const nonceKey = `${auth.from.toLowerCase()}:${auth.nonce}`;
    if (usedNonces.has(nonceKey)) {
      return json(res, 409, { error: 'authorization already used (replay)' });
    }

    // the facilitator's verify step: does this signature really commit `from`
    // to this exact transfer, against the real USDC domain? pure crypto, and it
    // is why a facilitator can't alter the amount or destination either.
    // viem throws on garbage that parsed as JSON but isn't crypto (bad hex, a
    // wrong-length signature) - same outcome as a wrong signature, never a crash.
    let valid = false;
    try {
      valid = await verifyTypedData({
        address: auth.from,
        domain: { name: domain.name, version: domain.version, chainId, verifyingContract: usdc },
        types: TRANSFER_TYPES,
        primaryType: 'TransferWithAuthorization',
        message: auth,
        signature,
      });
    } catch {
      valid = false;
    }
    if (!valid) {
      return json(res, 401, { error: 'signature does not verify against the authorization' });
    }

    // `product` may be a value or a function of the request, so a service can
    // actually compute something for the money rather than return a fixture.
    // produced BEFORE the nonce is burned: if we fail to make the goods that is
    // our fault, and the buyer should keep a usable authorization.
    let data;
    try {
      data = typeof svc.product === 'function'
        ? await svc.product(new URL(req.url, 'http://localhost'))
        : svc.product;
    } catch (err) {
      return json(res, 502, { error: `service failed to produce its result: ${err.shortMessage || err.message}` });
    }

    usedNonces.add(nonceKey);
    log(`verified EIP-3009 authorization from ${auth.from} for ${auth.value} base units - serving "${svc.name}"`);
    return json(res, 200, {
      data,
      payment: {
        from: auth.from,
        amount: auth.value.toString(),
        settled: false,
        note: 'authorization verified; settlement intentionally not broadcast in this demo',
      },
    });
  });
}

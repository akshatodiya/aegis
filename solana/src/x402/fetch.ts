// The Aegis x402 fetch wrapper: where the decision gets made.
//
// A plain x402 client sees a 402, signs a payment and retries, no questions
// asked. Aegis slots in between. On a 402 it reads the PaymentRequirements and,
// before anything is signed, asks what needs context the signer doesn't have:
//   - can we pay this at all (exact scheme, our network, the pinned USDC, a fee
//     payer that isn't us, a memo that is an invoice id)?
//   - is payTo a service we know (the catalog)?
//   - is the demand within its posted price (bait-and-switch)?
//   - is it over the per-payment cap (then a human decides)?
// Only then does it build the payment and hand it to the Aegis signer, which
// re-checks everything from the transaction bytes and runs the policy engine on
// the payee. Two call sites, one policy.
//
// It builds the payment itself rather than through an SDK, so every field we
// sign is one we chose, and it takes the blockhash from our own pinned RPC,
// never from the 402. Amounts are base units end to end. A hostile or
// malformed 402 fails closed with AegisPaymentRefused, never a crash.
import { randomBytes } from "crypto";
import { ComputeBudgetProgram, MessageV0, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { createTransferCheckedInstruction } from "@solana/spl-token";

import { describeError } from "../chain/confirm";
import { DEVNET_GENESIS_HASH, MEMO_PROGRAM, TOKEN_PROGRAM, USDC_DECIMALS, USDC_MINT, X402_NETWORK, caip2 } from "../config";
import { associatedTokenAddress } from "../guard/layout";
import { Fact, inspect } from "../lanes/inspection";
import { REFUSAL, RefusalCode } from "../refusals";
import { cleanText } from "../text";
import { Catalog, Service, canonicalAddress, canonicalOrigin } from "./catalog";
import { AegisPaymentRefused, OnRefuse, ResourceInfo, fireRefusal } from "./refused";
import { SvmRpc } from "./rpc";
import { AegisSigner, MEMO_RULE } from "./signer";
import { encodeTransaction } from "./wire";

const U64_MAX = (1n << 64n) - 1n;
/** How much of the seller's copy we carry, in characters. */
const LIMITS = { url: 200, description: 160, mimeType: 64 };
/** A 402 header bigger than this is not read. */
const MAX_HEADER_CHARS = 64_000;
const MAX_BODY_BYTES = 64_000;
/** v1 network names, mapped to CAIP-2. Anything else is not ours. */
const V1_NETWORKS: Record<string, string> = { "solana-devnet": caip2(DEVNET_GENESIS_HASH) };

export const DEFAULT_COMPUTE_UNITS = 20_000;
export const DEFAULT_MICRO_LAMPORTS = 1n;

/** The question an over-cap payment puts to a person. Only `true` approves. */
export interface ApprovalRequest {
  /** What our catalog says the service is. */
  service: Service;
  amount: bigint;
  cap: bigint;
  /** What the seller says it is selling: cleaned, possibly null, never ours. Show it apart. */
  resource: ResourceInfo | null;
  /** The URL the agent actually asked for, which may differ from the one the 402 describes. */
  requestUrl: string;
}
export type AskHuman = (q: ApprovalRequest) => Promise<boolean | null | undefined>;

export interface X402FetchOptions {
  signer: AegisSigner;
  catalog: Catalog;
  /** Our pinned RPC: the blockhash comes from here, never from the 402. */
  rpc: SvmRpc;
  network?: string;
  usdc?: PublicKey;
  /** Must preserve Response.url, including the final URL after redirects. */
  fetchImpl?: typeof fetch;
  /** Per-payment cap in base units; over it a human decides. null = no cap. */
  maxPerPayment?: bigint | null;
  /** No handler means nobody to ask, which is a no. */
  askHuman?: AskHuman | null;
  onRefuse?: OnRefuse | null;
  log?: (msg: string) => void;
  computeUnits?: number;
  microLamports?: bigint;
  /** What the inspection lane finds on a mint we were offered instead of USDC (for the person reading the refusal). */
  describeOffer?: ((asset: PublicKey, payTo: PublicKey) => Promise<Fact[]>) | null;
  /** The memo when the 402 sets none: 16 random bytes, hex. Injected only by tests. */
  randomMemo?: () => string;
}

interface Option {
  raw: Record<string, unknown>;
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  feePayer: string;
  amount: bigint;
  memo: string | undefined;
  resource: ResourceInfo | null;
}

/**
 * Cleans one piece of seller text: control bytes become spaces, invisible
 * characters go, whitespace collapses, length is capped. What survives is
 * quoted and attributed when shown. It defangs the formatting, not the
 * meaning: the text can still lie.
 */
export function resourceInfo(source: unknown): ResourceInfo | null {
  if (!source || typeof source !== "object") return null;
  const s = source as Record<string, any>;
  const raw = s.resource;
  const obj = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const url = cleanText(typeof raw === "string" ? raw : obj.url, LIMITS.url);
  const description = cleanText(obj.description ?? s.description, LIMITS.description);
  const mimeType = cleanText(obj.mimeType ?? s.mimeType, LIMITS.mimeType);
  return url || description || mimeType ? { url, description, mimeType } : null;
}

/** The fallback body is untrusted too: stop reading before it grows without bound. */
async function boundedJson(res: Response): Promise<any | null> {
  const body = res.clone().body;
  if (!body) return null;
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        void reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
}

/** The PaymentRequired document from a 402: the base64 header first, else the JSON body. */
export async function parseRequirements(res: Response): Promise<{ doc: Record<string, any> | null; options: unknown[]; version: 1 | 2; resource: ResourceInfo | null }> {
  const header = res.headers.get("payment-required") ?? res.headers.get("x-payment-required");
  let doc: any = null;
  let fromHeader = false;
  if (header && header.length <= MAX_HEADER_CHARS) {
    try {
      doc = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
      fromHeader = true;
    } catch {
      doc = null;
    }
  }
  if (!doc) doc = await boundedJson(res);
  if (!doc || typeof doc !== "object") return { doc: null, options: [], version: 2, resource: null };
  const options: unknown[] = Array.isArray(doc) ? doc : Array.isArray(doc.accepts) ? doc.accepts : [doc];
  let version: 1 | 2 = 2;
  if (Number(doc.x402Version) === 1) version = 1;
  else if (!fromHeader && options.some((o: any) => o && o.maxAmountRequired != null && o.amount == null)) version = 1;
  return { doc: Array.isArray(doc) ? null : doc, options, version, resource: resourceInfo(doc) };
}

/** One requirement, validated. Throws on anything malformed; the caller skips it. */
function normalize(opt: unknown): Option {
  if (!opt || typeof opt !== "object" || Array.isArray(opt)) throw new Error("not an object");
  const o = opt as Record<string, any>;
  // A decimal string, as the spec says. A JSON number over 2^53 has already lost digits.
  const amountText = o.amount ?? o.maxAmountRequired;
  if (typeof amountText !== "string" || !/^[1-9][0-9]*$/.test(amountText) || BigInt(amountText) > U64_MAX) {
    throw new Error(`bad amount ${JSON.stringify(amountText)}`);
  }
  if (o.maxTimeoutSeconds !== undefined && !(typeof o.maxTimeoutSeconds === "number" && Number.isFinite(o.maxTimeoutSeconds) && o.maxTimeoutSeconds >= 0)) {
    throw new Error("bad maxTimeoutSeconds");
  }
  const asset = canonicalAddress(o.asset);
  const payTo = canonicalAddress(o.payTo);
  const extra = o.extra && typeof o.extra === "object" ? o.extra : {};
  const feePayer = canonicalAddress(extra.feePayer);
  if (!asset || !payTo || !feePayer) throw new Error("asset, payTo and extra.feePayer must be base58 addresses");
  // An empty memo counts as none, as the reference client and facilitator treat it.
  const memo = extra.memo === undefined || extra.memo === "" ? undefined : extra.memo;
  if (memo !== undefined && !(typeof memo === "string" && MEMO_RULE.test(memo))) throw new Error("extra.memo is not an invoice id");
  // Protocol-reserved keys: a flow we don't recognize is not one we may pay
  // (spec v2). Only the default flow, which settles after delivery, is paid.
  if (extra.paymentFlow !== undefined && extra.paymentFlow !== "authorization") throw new Error(`payment flow ${JSON.stringify(extra.paymentFlow)} is not supported`);
  if (extra.assetTransferMethod !== undefined && extra.assetTransferMethod !== "default") throw new Error("unknown asset transfer method");
  const network = typeof o.network === "string" ? (V1_NETWORKS[o.network] ?? o.network) : "";
  return {
    raw: o,
    scheme: String(o.scheme),
    network,
    asset,
    payTo,
    feePayer,
    amount: BigInt(amountText),
    memo,
    resource: resourceInfo(o),
  };
}

/** Reads the PAYMENT-RESPONSE receipt a merchant returns with a paid response. null if absent or unreadable. */
export function paymentResponse(res: Response): Record<string, unknown> | null {
  const h = res.headers.get("payment-response") ?? res.headers.get("x-payment-response");
  if (!h || h.length > MAX_HEADER_CHARS) return null;
  try {
    const v = JSON.parse(Buffer.from(h, "base64").toString("utf8"));
    return v && typeof v === "object" ? v : null;
  } catch {
    return null;
  }
}

function href(url: unknown): string {
  if (typeof url === "string") return url;
  return typeof (url as any)?.url === "string" ? (url as any).url : String(url);
}

function originOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return canonicalOrigin(parsed.origin);
  } catch {
    return null;
  }
}

export function createAegisX402Fetch(opts: X402FetchOptions) {
  const {
    signer,
    catalog,
    rpc,
    network = X402_NETWORK,
    usdc = USDC_MINT,
    fetchImpl = fetch,
    maxPerPayment = null,
    askHuman = null,
    onRefuse = null,
    log = () => {},
    computeUnits = DEFAULT_COMPUTE_UNITS,
    microLamports = DEFAULT_MICRO_LAMPORTS,
    randomMemo = () => randomBytes(16).toString("hex"),
  } = opts;
  if (!signer) throw new Error("createAegisX402Fetch needs an Aegis signer");
  if (!catalog) throw new Error("createAegisX402Fetch needs a service catalog");
  const describeOffer =
    opts.describeOffer === undefined
      ? async (asset: PublicKey, payTo: PublicKey) => (await inspect(payTo, { reader: rpc.reader, guard: null, mint: asset })).facts.filter((f) => f.subject === "mint")
      : opts.describeOffer;
  const us = signer.address;

  /** The options we could pay, in order; and the first on our network that offered another asset. */
  function screen(options: unknown[]) {
    let payable: Option | null = null;
    let otherAsset: Option | null = null;
    for (const raw of options) {
      let o: Option;
      try {
        o = normalize(raw);
      } catch {
        continue; // a poison option can't hide a valid one behind it
      }
      if (o.scheme !== "exact" || o.network !== network || o.feePayer === us || o.payTo === us) continue;
      if (o.asset !== usdc.toBase58()) {
        otherAsset ??= o;
        continue;
      }
      payable = o;
      break;
    }
    return { payable, otherAsset };
  }

  async function pay(option: Option, version: 1 | 2, doc: Record<string, any> | null): Promise<string> {
    let blockhash: string;
    try {
      ({ blockhash } = await rpc.latestBlockhash());
    } catch (err) {
      throw new AegisPaymentRefused(`could not get a blockhash from our RPC (${describeError(err)}).`, "ASK_HUMAN", {
        code: REFUSAL.LANE_UNAVAILABLE,
        recipient: option.payTo,
        amount: option.amount,
      });
    }
    const payer = new PublicKey(us);
    const payTo = new PublicKey(option.payTo);
    const memo = option.memo ?? randomMemo();
    const instructions = [
      ComputeBudgetProgram.setComputeUnitLimit({ units: computeUnits }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports }),
      createTransferCheckedInstruction(associatedTokenAddress(payer, usdc), usdc, associatedTokenAddress(payTo, usdc), payer, option.amount, USDC_DECIMALS, [], TOKEN_PROGRAM),
      new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [], data: Buffer.from(memo, "utf8") }),
    ];
    const messageBytes = MessageV0.compile({ payerKey: new PublicKey(option.feePayer), recentBlockhash: blockhash, instructions }).serialize();
    // The signer re-derives and re-checks everything from these bytes; if it
    // refuses, it throws and no signature exists.
    const [signed] = await signer.signTransactions([{ messageBytes, signatures: { [option.feePayer]: null, [us]: null } }]);
    const transaction = Buffer.from(encodeTransaction([new Uint8Array(64), signed[us]], messageBytes)).toString("base64");
    const payload =
      version === 1
        ? { x402Version: 1, scheme: "exact", network: option.raw.network, payload: { transaction } }
        : {
            x402Version: 2,
            ...(doc?.resource !== undefined ? { resource: doc.resource } : {}),
            accepted: option.raw,
            payload: { transaction },
            ...(doc?.extensions !== undefined ? { extensions: doc.extensions } : {}),
          };
    return Buffer.from(JSON.stringify(payload)).toString("base64");
  }

  async function attempt(url: Parameters<typeof fetch>[0], init: RequestInit): Promise<Response> {
    // A Request or a streamed body can be consumed by the first fetch. Keep an
    // untouched copy for the paid retry before sending the first request.
    const replay = url instanceof Request || init.body != null ? new Request(url, init) : null;
    const res = replay ? await fetchImpl(replay.clone()) : await fetchImpl(url, init);
    if (res.status !== 402) return res;

    log(`402 from ${href(url)}: screening the payment demand...`);
    const { doc, options, version, resource: offered } = await parseRequirements(res);
    const { payable: option, otherAsset } = screen(options);
    if (!option) {
      // Nobody named yet, but the document still said what it was selling, and
      // for another asset the lane says what that mint could do to a holder.
      let offeredAsset: { mint: string; facts: Fact[] } | null = null;
      if (otherAsset && describeOffer) {
        try {
          offeredAsset = { mint: otherAsset.asset, facts: await describeOffer(new PublicKey(otherAsset.asset), new PublicKey(otherAsset.payTo)) };
        } catch {
          offeredAsset = null; // information only; never a reason to pay or not
        }
      }
      throw new AegisPaymentRefused(
        `no acceptable payment option: need the exact scheme on ${network} in USDC ${usdc.toBase58()}, with a fee payer other than us and a memo that is an invoice id.`,
        "BLOCK",
        { code: REFUSAL.NO_PAYABLE_OPTION, resource: offered, offeredAsset }
      );
    }

    // The requirement's own resource (v1) if it has one, else the document's (v2).
    const resource = option.resource ?? offered;
    const about = { recipient: option.payTo, amount: option.amount, resource };
    const refuse = (code: RefusalCode, reason: string, verdict: "BLOCK" | "ASK_HUMAN" = "BLOCK"): never => {
      throw new AegisPaymentRefused(reason, verdict, { code, ...about });
    };

    // (A) context the signer can't check: the service at the URL we asked for,
    // with the payTo and price we listed. A redirect's final URL must agree too.
    const service = catalog.lookup(option.payTo);
    const requestOrigin = originOf(href(url));
    const responseOrigin = originOf(res.url);
    if (!service || service.origin !== requestOrigin || service.origin !== responseOrigin) {
      refuse(REFUSAL.UNKNOWN_SERVICE, `payTo ${option.payTo} was not offered by its catalogued origin; refusing to pay an unknown service.`);
    }
    if (option.amount > service!.maxPrice) {
      refuse(REFUSAL.OVER_POSTED_PRICE, `bait-and-switch: "${service!.name}" demands ${option.amount} base units, over its posted ${service!.maxPrice}.`);
    }

    // Honest but big: over the cap a person decides, and the signer still runs after a yes.
    if (maxPerPayment !== null && option.amount > maxPerPayment) {
      log(`  "${service!.name}" costs ${option.amount} base units, over the ${maxPerPayment} per-payment cap: asking a human.`);
      let answer: boolean | null | undefined = null;
      let promptFailed: string | null = null;
      if (askHuman) {
        try {
          answer = await askHuman({ service: service!, amount: option.amount, cap: maxPerPayment, resource, requestUrl: href(url) });
        } catch (err) {
          promptFailed = describeError(err);
        }
      }
      if (answer !== true) {
        const overCap = `${option.amount} > cap ${maxPerPayment} base units`;
        if (promptFailed) refuse(REFUSAL.APPROVER_FAILED, `the over-cap approval prompt failed (${promptFailed}); nobody answered, so this is a no.`, "ASK_HUMAN");
        if (!askHuman) refuse(REFUSAL.NO_APPROVER, `payment of ${option.amount} base units exceeds the per-payment cap ${maxPerPayment} and no human is wired in to approve it.`, "ASK_HUMAN");
        if (answer == null) refuse(REFUSAL.NO_APPROVER, `nobody was available to approve the over-cap payment (${overCap}).`, "ASK_HUMAN");
        refuse(REFUSAL.HUMAN_DECLINED, `a human declined the over-cap payment (${overCap}).`, "ASK_HUMAN");
      }
      log("  a human approved the over-cap payment.");
    }

    log(`  known service "${service!.name}", ${option.amount} <= posted ${service!.maxPrice}. Signing...`);
    let header: string;
    try {
      header = await pay(option, version, doc);
    } catch (err) {
      // The signer can't know what was being sold; say it here, and only if empty.
      if (err instanceof AegisPaymentRefused && err.resource == null) err.resource = resource;
      throw err;
    }
    const headers = new Headers(replay?.headers ?? init.headers ?? {});
    headers.set(version === 1 ? "X-PAYMENT" : "PAYMENT-SIGNATURE", header);
    log("  payment signed and attached; retrying the request.");
    // Do not forward a signed payment header across a redirect on the retry.
    return replay ? fetchImpl(replay, { headers, redirect: "manual" }) : fetchImpl(url, { ...init, headers, redirect: "manual" });
  }

  // One place to notice a refusal, whichever check raised it. One refusal
  // through both hooks is still one: the audit logger dedupes on identity.
  return async function aegisFetch(url: Parameters<typeof fetch>[0], init: RequestInit = {}): Promise<Response> {
    try {
      return await attempt(url, init);
    } catch (err) {
      if (err instanceof AegisPaymentRefused) fireRefusal(onRefuse, err);
      throw err;
    }
  };
}

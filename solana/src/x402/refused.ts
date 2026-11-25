// The one error both x402 hooks throw when they decline to pay. It carries the
// prose reason (for people), a refusal code (for programs), and who we declined
// to pay and how much, when we got far enough to know.
import type { Fact } from "../lanes/inspection";
import { RefusalCode } from "../refusals";

export type RefusalVerdict = "BLOCK" | "ASK_HUMAN";

/** What the seller says it is selling, cleaned. Shown, never compared, never signed. */
export interface ResourceInfo {
  url: string | null;
  description: string | null;
  mimeType: string | null;
}

export interface RefusalAbout {
  code: RefusalCode;
  /** The payee we declined: payTo from the 402, or the owner of the destination the signer read. */
  recipient?: string | null;
  /** Base units. */
  amount?: bigint | null;
  resource?: ResourceInfo | null;
  /** For NO_PAYABLE_OPTION on another asset: what the inspection lane found on the offered mint. */
  offeredAsset?: { mint: string; facts: Fact[] } | null;
}

export class AegisPaymentRefused extends Error {
  readonly verdict: RefusalVerdict;
  readonly reason: string;
  readonly code: RefusalCode;
  readonly recipient: string | null;
  readonly amount: bigint | null;
  /**
   * Seller text, kept apart from `reason` on purpose: the reason may be written
   * on-chain as a receipt, and the seller doesn't get to choose what it says.
   * The fetch wrapper fills it in for a signer refusal, which can't know it.
   */
  resource: ResourceInfo | null;
  readonly offeredAsset: { mint: string; facts: Fact[] } | null;

  constructor(reason: string, verdict: RefusalVerdict, about: RefusalAbout) {
    super(`Aegis refused to sign this x402 payment: ${reason}`);
    this.name = "AegisPaymentRefused";
    this.verdict = verdict;
    this.reason = reason;
    this.code = about.code;
    this.recipient = about.recipient ?? null;
    this.amount = about.amount ?? null;
    this.resource = about.resource ?? null;
    this.offeredAsset = about.offeredAsset ?? null;
  }
}

export type OnRefuse = (err: AegisPaymentRefused) => void;

/** A hook must not throw into the refusal path, and must not block it. */
export function fireRefusal(onRefuse: OnRefuse | null | undefined, err: AegisPaymentRefused): void {
  if (!onRefuse) return;
  try {
    onRefuse(err);
  } catch {
    // a broken hook is not a reason to change what we tell the caller
  }
}

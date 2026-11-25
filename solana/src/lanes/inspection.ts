// Inspection lane: what the recipient is and who controls it, read from account
// data. The Solana counterpart of the EVM bytecode lane. On Solana the red flags
// live in accounts, not code: who owns the recipient's data, whether that
// program can still be upgraded, and what state the recipient's USDC account
// is in (owner, frozen, delegate). For an asset other than USDC it also reads
// the mint's Token-2022 extensions.
//
// Three rules carried over from the EVM lane:
//  - It reads facts, it does not guess. Every fact names the bytes it came from.
//  - A false negative is the one direction it may not fail in. A read error is
//    UNKNOWN (never "no account, so a fresh wallet"), and a decode error or an
//    unknown extension is a finding, never a pass.
//  - Naming a known program says what its trust rests on. It never zeroes a risk.
import { PublicKey } from "@solana/web3.js";

import { AccountReader, RawAccount } from "../chain/reader";
import {
  DecodeError,
  Extension,
  MINT_LEN,
  MULTISIG_LEN,
  TOKEN_ACCOUNT_LEN,
  decodeClassicMint,
  decodeLoaderV3,
  decodeLoaderV4,
  decodeToken2022Mint,
  decodeTokenAccount,
  MintData,
} from "../chain/decode";
import {
  BPF_LOADER_1,
  BPF_LOADER_2,
  BPF_LOADER_UPGRADEABLE,
  CONFIG_PROGRAM,
  INCINERATOR,
  LOADERS,
  LOADER_V4,
  NATIVE_LOADER,
  RECENT_DEPLOY_SLOTS,
  STAKE_PROGRAM,
  SYSTEM_PROGRAM,
  SYSVAR_OWNER,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
  USDC_MINT,
  VOTE_PROGRAM,
} from "../config";
import { GuardPdas, associatedTokenAddress, readConfig, readEntry } from "../guard/layout";
import { knownMint, knownProgram } from "../registry";
import { cleanText } from "../text";
import { formatUnits } from "../units";

export type Level = "LOW" | "MEDIUM" | "HIGH";
export type FactSubject = "recipient" | "destination" | "program" | "mint";

export type FactId =
  // what the recipient is
  | "SINK_RECIPIENT"
  | "PROGRAM_RECIPIENT"
  | "TOKEN_ACCOUNT_RECIPIENT"
  | "SYSVAR_RECIPIENT"
  | "NATIVE_PROGRAM_ACCOUNT"
  | "WALLET"
  | "SYSTEM_ACCOUNT_WITH_DATA"
  | "OFF_CURVE_RECIPIENT"
  | "PROGRAM_CONTROLLED"
  | "UNKNOWN_CONTROLLER"
  | "ALLOWLISTED"
  // the program that controls it
  | "BLOCKED_PROGRAM"
  | "CLOSED_PROGRAM"
  | "UPGRADEABLE_PROGRAM"
  | "RECENTLY_DEPLOYED"
  | "IMMUTABLE_PROGRAM"
  // its USDC account
  | "DESTINATION_MISSING"
  | "BAD_DESTINATION"
  | "DESTINATION_OWNER_MISMATCH"
  | "FROZEN_DESTINATION"
  | "DELEGATED_DESTINATION"
  | "DESTINATION_CLOSE_AUTHORITY"
  | "NON_CANONICAL_DESTINATION"
  // an asset other than USDC
  | "NOT_PINNED_ASSET"
  | "BAD_MINT"
  | "PERMANENT_DELEGATE"
  | "SPOOFED_METADATA"
  | "METADATA_MISMATCH"
  | "EXTERNAL_METADATA"
  | "UNKNOWN_EXTENSION"
  | "TRANSFER_HOOK"
  | "TRANSFER_FEE"
  | "FREEZE_AUTHORITY"
  | "MINT_AUTHORITY"
  | "DEFAULT_FROZEN"
  | "NON_TRANSFERABLE"
  | "PAUSABLE"
  | "MINT_CLOSE_AUTHORITY"
  | "CONFIDENTIAL_TRANSFER"
  | "UI_AMOUNT_ADJUSTED";

export interface Fact {
  id: FactId;
  level: Level;
  subject: FactSubject;
  /** aegis_guard refuses this recipient type on-chain by itself, whatever its lists say. */
  guardEnforced?: boolean;
  detail: string;
  data?: Record<string, string | number | boolean | null>;
}

export type RecipientKind =
  | "sink"
  | "wallet"
  | "system-account"
  | "pda"
  | "program-owned"
  | "program"
  | "token-account"
  | "sysvar"
  | "native-account";

export interface ProgramInfo {
  id: string;
  name: string | null;
  loader: "upgradeable" | "loader-v2" | "loader-v1" | "loader-v4" | "native" | "none";
  closed: boolean;
  upgradeAuthority: string | null;
  deploySlot: number | null;
  blocked: boolean | null;
}

export interface DestinationInfo {
  address: string;
  canonical: boolean;
  exists: boolean;
  owner: string | null;
  mint: string | null;
  state: string | null;
  delegate: string | null;
  delegatedAmount: string | null;
  closeAuthority: string | null;
}

export interface OnchainLists {
  denied: boolean;
  allow: { controller: string | null } | null;
}

export interface Inspection {
  lane: "inspection";
  recipient: string;
  /** UNKNOWN when a read failed: the facts are partial and nothing may pass on them. */
  level: Level | "UNKNOWN";
  kind: RecipientKind | null;
  facts: Fact[];
  /**
   * Program that can sign for the recipient's USDC account, when that is known:
   * the controller the guard owner named in an allow entry. Never just the
   * recipient's data owner, which for an off-curve address need not be the
   * program that derived it.
   */
  controller: string | null;
  programs: ProgramInfo[];
  destination: DestinationInfo | null;
  /** The guard's own lists for this recipient; null when no guard is configured. */
  onchain: OnchainLists | null;
  reason: string;
  error?: string;
}

export interface InspectOptions {
  reader: AccountReader;
  /** The aegis_guard program id, to read its lists. null or absent: lists are skipped (`onchain` is null; aegisCheck says so). */
  guard?: PublicKey | null;
  /** Payment size in base units, compared against a delegate's allowance. Absent = assume the worst. */
  amount?: bigint;
  /** An explicit destination token account (x402). Default: ATA(recipient, USDC). */
  destination?: PublicKey;
  /** An asset other than USDC to inspect, e.g. the mint an x402 offer names. */
  mint?: PublicKey;
  /** Override the pinned USDC mint (tests only). */
  usdcMint?: PublicKey;
  /** How recent a deploy counts as "new". Default about one epoch; a fresh test validator needs 0. */
  recentDeploySlots?: number;
}

const RANK: Record<Level, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };
// ProgramData and loader-v4 headers, and entry accounts (8 + 32 + 1), all fit in 48 bytes.
const HEADER_SLICE = { offset: 0, length: 48 };

export async function inspect(recipientIn: PublicKey | string, opts: InspectOptions): Promise<Inspection> {
  const recipient = new PublicKey(recipientIn);
  const usdc = opts.usdcMint ?? USDC_MINT;
  const pdas = opts.guard ? new GuardPdas(opts.guard) : null;
  const ata = associatedTokenAddress(recipient, usdc);
  const destinationAddr = opts.destination ?? ata;
  const foreignMint = opts.mint && !opts.mint.equals(usdc) ? opts.mint : null;

  const out: Inspection = {
    lane: "inspection",
    recipient: recipient.toBase58(),
    level: "LOW",
    kind: null,
    facts: [],
    controller: null,
    programs: [],
    destination: null,
    onchain: null,
    reason: "",
  };
  const add = (f: Fact) => out.facts.push(f);

  try {
    // ---- round 1: the recipient, its USDC account, the guard's entries, the offered mint ----
    const keys: PublicKey[] = [recipient, destinationAddr];
    if (pdas) keys.push(pdas.entry("deny", recipient), pdas.entry("allow", recipient), pdas.config);
    if (foreignMint) keys.push(foreignMint);
    const r1 = await opts.reader.getAccounts(keys);
    const acct = r1[0];
    const dest = r1[1];
    let allowController: PublicKey | null = null;
    let vault: PublicKey | null = null;
    if (pdas) {
      const deny = readEntry(r1[2], pdas.programId);
      const allow = readEntry(r1[3], pdas.programId);
      allowController = allow?.controller ?? null;
      out.onchain = {
        denied: deny !== null,
        allow: allow ? { controller: allow.controller?.toBase58() ?? null } : null,
      };
      const config = readConfig(r1[4], pdas.programId);
      // No config: wrong cluster, wrong id, or not initialized. Its lists would
      // read as empty, which is not the same as "not listed".
      if (!config) throw new Error(`aegis_guard ${pdas.programId.toBase58()} has no config account on this cluster`);
      vault = config.vault;
      if (allow) {
        add({
          id: "ALLOWLISTED",
          level: "LOW",
          subject: "recipient",
          detail: `The guard owner allowlisted this recipient on-chain${allow.controller ? ` (controller ${allow.controller.toBase58()})` : ""}.`,
          data: { controller: allow.controller?.toBase58() ?? null },
        });
      }
    }
    const mintAcct = foreignMint ? r1[r1.length - 1] : null;

    // ---- what the recipient is ----
    const sink = sinkName(recipient, acct, pdas, vault);
    const controllers: PublicKey[] = [];
    if (sink) {
      out.kind = "sink";
      add({ id: "SINK_RECIPIENT", level: "HIGH", subject: "recipient", guardEnforced: true, detail: `Recipient is ${sink}: tokens sent there are lost or land in Aegis's own accounts.` });
    } else {
      classifyRecipient(recipient, acct, allowController, out, controllers);
    }

    // ---- its USDC account, and an asset other than USDC (both read in round 1) ----
    if (!out.facts.some((f) => f.guardEnforced)) {
      out.destination = destinationFacts(recipient, destinationAddr, destinationAddr.equals(ata), dest, usdc, opts.amount, add);
    }
    if (foreignMint) mintFacts(foreignMint, mintAcct, add);

    // ---- round 2: the programs behind it, their block entries, the slot ----
    const programIds = uniqueKeys([
      ...controllers,
      ...(out.kind === "program" && acct && isProgramAccount(acct.owner, acct) ? [recipient] : []),
    ]);
    if (programIds.length > 0) {
      const r2Keys: PublicKey[] = [];
      for (const id of programIds) {
        r2Keys.push(id, programDataAddress(id));
        if (pdas) r2Keys.push(pdas.entry("blockprog", id));
      }
      const [r2, slot] = await Promise.all([opts.reader.getAccounts(r2Keys, HEADER_SLICE), opts.reader.getSlot()]);
      const stride = pdas ? 3 : 2;
      programIds.forEach((id, i) => {
        const programAcct = id.equals(recipient) ? acct : r2[i * stride];
        const blocked = pdas ? readEntry(r2[i * stride + 2], pdas.programId) !== null : null;
        const info = readProgram(id, programAcct, r2[i * stride + 1], blocked);
        out.programs.push(info);
        // The recipient itself, when it really is a program: already HIGH as
        // one. An account that names itself as its owner is not, and is judged
        // like any other owner.
        if (out.kind === "program" && id.equals(recipient)) return;
        programFacts(info, slot, opts.recentDeploySlots ?? RECENT_DEPLOY_SLOTS, add);
      });
    }
  } catch (err) {
    out.error = err instanceof Error ? err.message : String(err);
    // A HIGH fact already read is exact; a later read failing doesn't unprove it.
    if (out.facts.some((f) => f.level === "HIGH")) {
      out.level = "HIGH";
      out.reason = `${summarize({ ...out, level: "HIGH" })} (Later reads failed: ${out.error}. The facts above are partial.)`;
      return out;
    }
    out.level = "UNKNOWN";
    out.reason = `Could not read the recipient's accounts (${out.error}). Nothing is known, so nothing may pass on this lane.`;
    return out;
  }

  out.level = out.facts.reduce<Level>((lvl, f) => (RANK[f.level] > RANK[lvl] ? f.level : lvl), "LOW");
  out.reason = summarize(out);
  return out;
}

// ---- recipient classification ----

function sinkName(recipient: PublicKey, acct: RawAccount | null, pdas: GuardPdas | null, vault: PublicKey | null): string | null {
  if (recipient.equals(PublicKey.default)) return "the default key (the System Program id)";
  if (recipient.equals(INCINERATOR)) return "the incinerator, where anyone can burn tokens";
  if (pdas) {
    if (recipient.equals(pdas.config)) return "the guard's config account";
    if (recipient.equals(pdas.audit)) return "the guard's audit log";
    if (vault && recipient.equals(vault)) return "the guard's own vault";
    if (acct && acct.owner.equals(pdas.programId)) return "an account owned by the guard program";
  }
  return null;
}

function classifyRecipient(
  recipient: PublicKey,
  acct: RawAccount | null,
  allowController: PublicKey | null,
  out: Inspection,
  controllers: PublicKey[]
) {
  const add = (f: Fact) => out.facts.push(f);
  const onCurve = PublicKey.isOnCurve(recipient.toBytes());
  const owner = acct?.owner ?? SYSTEM_PROGRAM; // the runtime reports a missing account as System-owned

  if (acct && LOADERS.some((l) => l.equals(owner))) {
    out.kind = "program";
    add({
      id: "PROGRAM_RECIPIENT",
      level: "HIGH",
      subject: "recipient",
      guardEnforced: true,
      detail: `Recipient is ${loaderAccountKind(owner, acct)}${nameOf(recipient)}. A program can't sign for a token account at its own address, so a payment there is stranded.`,
    });
    return;
  }
  if (acct && (owner.equals(TOKEN_PROGRAM) || owner.equals(TOKEN_2022_PROGRAM))) {
    out.kind = "token-account";
    const what = tokenAccountKind(acct.data);
    add({
      id: "TOKEN_ACCOUNT_RECIPIENT",
      level: "HIGH",
      subject: "recipient",
      guardEnforced: true,
      detail: `Recipient is ${what}, not a wallet. A USDC account for it could never be spent.`,
    });
    return;
  }
  if (acct && owner.equals(SYSVAR_OWNER)) {
    out.kind = "sysvar";
    add({ id: "SYSVAR_RECIPIENT", level: "HIGH", subject: "recipient", guardEnforced: true, detail: "Recipient is a sysvar account. Nothing can spend from it." });
    return;
  }
  if (acct && [VOTE_PROGRAM, STAKE_PROGRAM, CONFIG_PROGRAM].some((p) => p.equals(owner))) {
    out.kind = "native-account";
    add({
      id: "NATIVE_PROGRAM_ACCOUNT",
      level: "HIGH",
      subject: "recipient",
      detail: `Recipient is a ${nameOf(owner, false) || owner.toBase58()} account (stake, vote or config state), not a payee.`,
    });
    return;
  }

  if (owner.equals(SYSTEM_PROGRAM)) {
    if (onCurve) {
      out.kind = acct && acct.data.length > 0 ? "system-account" : "wallet";
      if (acct && acct.data.length > 0) {
        add({
          id: "SYSTEM_ACCOUNT_WITH_DATA",
          level: "LOW",
          subject: "recipient",
          detail: `Recipient is a System-owned account holding ${acct.data.length} bytes of data (for example a durable nonce), at a keypair address.`,
        });
      } else {
        add({
          id: "WALLET",
          level: "LOW",
          subject: "recipient",
          detail: acct ? "Recipient is a plain wallet (System-owned, on the curve)." : "Recipient is a wallet address with no account yet (on the curve, so a keypair can sign for it).",
        });
      }
      return;
    }
    // Off the curve and holding no program data: only the program that derived
    // it can sign, and nothing on-chain says which program that is.
    out.kind = "pda";
    add({
      id: "OFF_CURVE_RECIPIENT",
      level: "LOW",
      subject: "recipient",
      detail: `Recipient is off the curve (a program address)${acct ? " with no program data" : " with no account"}: only the program that derived it can move what it holds.`,
    });
    if (allowController) {
      out.controller = allowController.toBase58();
      controllers.push(allowController);
    } else {
      add({
        id: "UNKNOWN_CONTROLLER",
        level: "MEDIUM",
        subject: "recipient",
        detail: "Nothing on-chain says which program controls it, so it can't be vetted from chain state.",
      });
    }
    return;
  }

  // Data owned by some other program. The guard checks that program's block
  // entry, so it is judged. But it is not necessarily who can move the USDC:
  //  - on the curve, a keypair signs for the USDC account;
  //  - off the curve, only the program that derived the address can, and that
  //    program can assign the data to any program it likes (an immutable one,
  //    to look safe). Only an allow entry's controller names the signer.
  out.kind = "program-owned";
  controllers.push(owner);
  add({
    id: "PROGRAM_CONTROLLED",
    level: "LOW",
    subject: "recipient",
    detail: `Recipient's data is owned by program ${owner.toBase58()}${nameOf(owner)}${onCurve ? ", although the address is on the curve, so a keypair signs for its USDC account" : ""}.`,
    data: { program: owner.toBase58(), onCurve },
  });
  if (allowController) {
    out.controller = allowController.toBase58();
    if (!allowController.equals(owner)) controllers.push(allowController);
  } else if (!onCurve) {
    add({
      id: "UNKNOWN_CONTROLLER",
      level: "MEDIUM",
      subject: "recipient",
      detail: `Recipient is off the curve, so only the program that derived it can move its USDC. Its data owner ${owner.toBase58()}${nameOf(owner)} need not be that program, and nothing on-chain says which one is.`,
      data: { dataOwner: owner.toBase58() },
    });
  }
}

function tokenAccountKind(data: Buffer): string {
  if (data.length === MINT_LEN) return "a token mint";
  if (data.length === TOKEN_ACCOUNT_LEN) return "a token account";
  if (data.length === MULTISIG_LEN) return "a token multisig";
  if (data.length > TOKEN_ACCOUNT_LEN && data[TOKEN_ACCOUNT_LEN] === 1) return "a token mint";
  if (data.length > TOKEN_ACCOUNT_LEN && data[TOKEN_ACCOUNT_LEN] === 2) return "a token account";
  return "an account owned by a token program";
}

/** True for an account that is itself executable program code, not ProgramData or a buffer. */
function isProgramAccount(owner: PublicKey, acct: RawAccount): boolean {
  if (owner.equals(BPF_LOADER_UPGRADEABLE)) {
    try {
      return decodeLoaderV3(acct.data).kind === "program";
    } catch {
      return false;
    }
  }
  return LOADERS.some((l) => l.equals(owner));
}

function loaderAccountKind(owner: PublicKey, acct: RawAccount): string {
  if (owner.equals(BPF_LOADER_UPGRADEABLE)) {
    try {
      const state = decodeLoaderV3(acct.data);
      if (state.kind === "programData") return "a program's ProgramData account";
      if (state.kind === "buffer") return "a program deploy buffer";
      if (state.kind === "program") return "a program";
    } catch {
      return "an account owned by the upgradeable loader";
    }
    return "an uninitialized loader account";
  }
  if (owner.equals(NATIVE_LOADER)) return "a native program";
  return "a program";
}

// ---- programs ----

function programDataAddress(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([programId.toBuffer()], BPF_LOADER_UPGRADEABLE)[0];
}

function readProgram(id: PublicKey, programAcct: RawAccount | null, programData: RawAccount | null, blocked: boolean | null): ProgramInfo {
  const info: ProgramInfo = {
    id: id.toBase58(),
    name: knownProgram(id)?.name ?? null,
    loader: "none",
    closed: false,
    upgradeAuthority: null,
    deploySlot: null,
    blocked,
  };
  if (!programAcct) {
    info.closed = true;
    return info;
  }
  const owner = programAcct.owner;
  if (owner.equals(BPF_LOADER_UPGRADEABLE)) {
    info.loader = "upgradeable";
    let state;
    try {
      state = decodeLoaderV3(programAcct.data);
    } catch {
      info.closed = true;
      return info;
    }
    if (state.kind !== "program" || !state.programData.equals(programDataAddress(id)) || !programData || !programData.owner.equals(BPF_LOADER_UPGRADEABLE)) {
      info.closed = true;
      return info;
    }
    let pd;
    try {
      pd = decodeLoaderV3(programData.data);
    } catch {
      info.closed = true;
      return info;
    }
    if (pd.kind !== "programData") {
      info.closed = true;
      return info;
    }
    info.deploySlot = Number(pd.slot);
    // An authority of all zeros is the System Program id: nobody can sign for it.
    info.upgradeAuthority = pd.authority && !pd.authority.equals(PublicKey.default) ? pd.authority.toBase58() : null;
    return info;
  }
  // Anyone can create a data-less account owned by these loaders; only a real
  // program is executable.
  if (owner.equals(BPF_LOADER_2)) {
    info.loader = "loader-v2";
    info.closed = !programAcct.executable;
    return info;
  }
  if (owner.equals(BPF_LOADER_1)) {
    info.loader = "loader-v1";
    info.closed = !programAcct.executable;
    return info;
  }
  if (owner.equals(NATIVE_LOADER)) {
    info.loader = "native";
    info.closed = !programAcct.executable;
    return info;
  }
  if (owner.equals(LOADER_V4)) {
    info.loader = "loader-v4";
    try {
      const v4 = decodeLoaderV4(programAcct.data);
      info.deploySlot = Number(v4.slot);
      if (v4.status === "retracted") info.closed = true;
      if (v4.status === "deployed") info.upgradeAuthority = v4.authorityOrNext.toBase58();
    } catch {
      info.closed = true;
    }
    return info;
  }
  // An "owner program" that is not a program at all: nothing can ever run for it.
  info.closed = true;
  return info;
}

function programFacts(info: ProgramInfo, slot: number, recentSlots: number, add: (f: Fact) => void) {
  const label = `program ${info.id}${info.name ? ` (${info.name})` : ""}`;
  if (info.blocked) {
    add({ id: "BLOCKED_PROGRAM", level: "HIGH", subject: "program", detail: `The guard blocks ${label} on-chain.`, data: { program: info.id } });
  }
  if (info.closed) {
    add({
      id: "CLOSED_PROGRAM",
      level: "HIGH",
      subject: "program",
      detail: `${cap(label)} is closed, retracted or not a program: funds in accounts it controls can't be moved.`,
      data: { program: info.id },
    });
    return;
  }
  if (info.upgradeAuthority) {
    add({
      id: "UPGRADEABLE_PROGRAM",
      level: "MEDIUM",
      subject: "program",
      detail: `${cap(label)} can be upgraded by ${info.upgradeAuthority}, so the logic guarding what we pay can change after we vet it${info.deploySlot !== null ? ` (last deployed at slot ${info.deploySlot})` : ""}.`,
      data: { program: info.id, upgradeAuthority: info.upgradeAuthority, deploySlot: info.deploySlot },
    });
  } else {
    add({
      id: "IMMUTABLE_PROGRAM",
      level: "LOW",
      subject: "program",
      detail: `${cap(label)} has no upgrade authority${info.loader === "native" ? " (native)" : ""}.`,
      data: { program: info.id, loader: info.loader },
    });
  }
  if (info.deploySlot !== null && slot - info.deploySlot < recentSlots) {
    add({
      id: "RECENTLY_DEPLOYED",
      level: "MEDIUM",
      subject: "program",
      detail: `${cap(label)} was deployed ${slot - info.deploySlot} slots ago, within about one epoch.`,
      data: { program: info.id, deploySlot: info.deploySlot, slot },
    });
  }
}

// ---- the destination USDC account ----

function destinationFacts(
  recipient: PublicKey,
  address: PublicKey,
  canonical: boolean,
  acct: RawAccount | null,
  usdc: PublicKey,
  amount: bigint | undefined,
  add: (f: Fact) => void
): DestinationInfo {
  const info: DestinationInfo = {
    address: address.toBase58(),
    canonical,
    exists: acct !== null,
    owner: null,
    mint: null,
    state: null,
    delegate: null,
    delegatedAmount: null,
    closeAuthority: null,
  };
  if (!canonical) {
    add({
      id: "NON_CANONICAL_DESTINATION",
      level: "MEDIUM",
      subject: "destination",
      detail: `Destination ${info.address} is not the recipient's associated USDC account.`,
    });
  }
  // Lamports at the ATA address are not an account anyone chose: a stranger can
  // send them, and the ATA can still be created there. So it reads as missing,
  // never as a bad destination (which would get the wallet denylisted).
  const lamportsOnly = acct !== null && canonical && acct.owner.equals(SYSTEM_PROGRAM) && acct.data.length === 0;
  if (!acct || lamportsOnly) {
    add({
      id: "DESTINATION_MISSING",
      level: "MEDIUM",
      subject: "destination",
      detail: lamportsOnly
        ? "Recipient has no USDC account yet, only lamports someone sent to its address. Paying means creating one there, and the payer funds its rent."
        : "Recipient has no USDC account yet. Paying means creating one, and the payer funds its rent.",
    });
    return info;
  }
  const bad = (why: string) =>
    add({ id: "BAD_DESTINATION", level: "HIGH", subject: "destination", detail: `Destination ${info.address} ${why}.` });
  if (!acct.owner.equals(TOKEN_PROGRAM)) {
    bad(acct.owner.equals(TOKEN_2022_PROGRAM) ? "is a Token-2022 account; USDC here is classic SPL Token" : "is not a token account");
    return info;
  }
  if (acct.data.length !== TOKEN_ACCOUNT_LEN) {
    bad(`has ${acct.data.length} bytes, not a ${TOKEN_ACCOUNT_LEN}-byte token account`);
    return info;
  }
  let t;
  try {
    t = decodeTokenAccount(acct.data);
  } catch (e) {
    bad(`could not be decoded (${e instanceof DecodeError ? e.message : String(e)})`);
    return info;
  }
  info.owner = t.owner.toBase58();
  info.mint = t.mint.toBase58();
  info.state = t.state;
  info.delegate = t.delegate?.toBase58() ?? null;
  info.delegatedAmount = t.delegate ? t.delegatedAmount.toString() : null;
  info.closeAuthority = t.closeAuthority?.toBase58() ?? null;

  if (t.state === "uninitialized") {
    bad("is not initialized");
    return info;
  }
  if (!t.mint.equals(usdc)) {
    bad(`holds mint ${info.mint}, not USDC`);
    return info;
  }
  if (!t.owner.equals(recipient)) {
    add({
      id: "DESTINATION_OWNER_MISMATCH",
      level: "HIGH",
      subject: "destination",
      detail: `Recipient's USDC account is owned by ${info.owner}, not by the recipient. Classic Token lets an account's owner be reassigned, so the address alone proves nothing.`,
      data: { actualOwner: info.owner },
    });
  }
  if (t.state === "frozen") {
    add({ id: "FROZEN_DESTINATION", level: "HIGH", subject: "destination", detail: "Recipient's USDC account is frozen. For USDC only the issuer can freeze, which usually means blacklisted." });
  }
  if (t.delegate && t.delegatedAmount > 0n) {
    const covers = amount === undefined || t.delegatedAmount >= amount;
    // Approve with u64::MAX is the usual "unlimited" allowance; say so instead of printing 18446744073709.551615.
    const allowance = t.delegatedAmount === 2n ** 64n - 1n ? "an unlimited amount of" : formatUnits(t.delegatedAmount);
    add({
      id: "DELEGATED_DESTINATION",
      level: covers ? "HIGH" : "MEDIUM",
      subject: "destination",
      detail: `Recipient's USDC account has a live delegate ${info.delegate} allowed to move ${allowance} USDC${covers ? ", enough to sweep this payment" : ""}.`,
      data: { delegate: info.delegate, delegatedAmount: info.delegatedAmount },
    });
  }
  if (t.closeAuthority && !t.closeAuthority.equals(recipient)) {
    add({
      id: "DESTINATION_CLOSE_AUTHORITY",
      level: "LOW",
      subject: "destination",
      detail: `Recipient's USDC account can be closed by ${info.closeAuthority} once it is empty.`,
    });
  }
  return info;
}

// ---- an asset other than USDC ----

function mintFacts(mint: PublicKey, acct: RawAccount | null, add: (f: Fact) => void) {
  const known = knownMint(mint);
  add({
    id: "NOT_PINNED_ASSET",
    level: "HIGH",
    subject: "mint",
    detail: `Mint ${mint.toBase58()}${known ? ` (${known.name})` : ""} is not the pinned USDC. Aegis only pays USDC; the findings below are for information.`,
  });
  const bad = (why: string) => add({ id: "BAD_MINT", level: "HIGH", subject: "mint", detail: `Mint ${mint.toBase58()} ${why}.` });
  if (!acct) return bad("does not exist");
  let m: MintData;
  try {
    if (acct.owner.equals(TOKEN_PROGRAM)) m = decodeClassicMint(acct.data);
    else if (acct.owner.equals(TOKEN_2022_PROGRAM)) m = decodeToken2022Mint(acct.data);
    else return bad("is not owned by a token program");
  } catch (e) {
    return bad(`could not be decoded (${e instanceof Error ? e.message : String(e)})`);
  }
  if (!m.isInitialized) return bad("is not initialized");

  const issuer = known ? `issuer trust (${known.issuer})` : null;
  if (m.freezeAuthority) {
    add({
      id: "FREEZE_AUTHORITY",
      level: issuer ? "LOW" : "MEDIUM",
      subject: "mint",
      detail: `${m.freezeAuthority.toBase58()} can freeze any holder's account${issuer ? `: ${issuer}` : ""}.`,
    });
  }
  if (m.mintAuthority) {
    add({ id: "MINT_AUTHORITY", level: "LOW", subject: "mint", detail: `${m.mintAuthority.toBase58()} can mint more.` });
  }
  for (const ext of m.extensions) extensionFact(mint, ext, known !== null, issuer, add);
}

function extensionFact(mint: PublicKey, ext: Extension, isKnown: boolean, issuer: string | null, add: (f: Fact) => void) {
  switch (ext.name) {
    case "Unknown":
      add({ id: "UNKNOWN_EXTENSION", level: "HIGH", subject: "mint", detail: `Mint carries extension type ${ext.type}, which this lane can't read.`, data: { type: ext.type } });
      return;
    case "PermanentDelegate":
      if ("delegate" in ext && ext.delegate) {
        add({
          id: "PERMANENT_DELEGATE",
          level: issuer ? "LOW" : "HIGH",
          subject: "mint",
          detail: `${ext.delegate.toBase58()} is a permanent delegate: it can move or burn any holder's balance${issuer ? `, ${issuer}` : ""}.`,
          data: { delegate: ext.delegate.toBase58() },
        });
      }
      return;
    case "TransferHook":
      if ("programId" in ext && (ext.programId || ext.authority)) {
        add({
          id: "TRANSFER_HOOK",
          level: ext.programId ? "MEDIUM" : "LOW",
          subject: "mint",
          detail: ext.programId
            ? `Every transfer runs hook program ${ext.programId.toBase58()}, which can make transfers fail.`
            : `${ext.authority!.toBase58()} can switch on a transfer hook later.`,
        });
      }
      return;
    case "TransferFeeConfig":
      if ("newerBps" in ext) {
        const bps = Math.max(ext.olderBps, ext.newerBps);
        if (bps > 0 || ext.configAuthority) {
          add({
            id: "TRANSFER_FEE",
            level: bps > 0 ? "MEDIUM" : "LOW",
            subject: "mint",
            detail: bps > 0 ? `Transfers pay a fee of up to ${bps} basis points; the recipient gets less than is sent.` : `Transfer fee is 0 now, but ${ext.configAuthority!.toBase58()} can raise it.`,
          });
        }
      }
      return;
    case "DefaultAccountState":
      if ("state" in ext && ext.state === "frozen") {
        add({ id: "DEFAULT_FROZEN", level: "MEDIUM", subject: "mint", detail: "New accounts for this mint start frozen until the issuer thaws them." });
      }
      return;
    case "NonTransferable":
      add({ id: "NON_TRANSFERABLE", level: "MEDIUM", subject: "mint", detail: "Tokens of this mint can't be transferred once received." });
      return;
    case "PausableConfig":
      if ("paused" in ext) {
        add({
          id: "PAUSABLE",
          level: ext.paused ? "MEDIUM" : "LOW",
          subject: "mint",
          detail: ext.paused ? "The mint is paused: every transfer fails." : `${ext.authority?.toBase58() ?? "An authority"} can pause every transfer.`,
        });
      }
      return;
    case "MintCloseAuthority":
      if ("authority" in ext && ext.authority) {
        add({ id: "MINT_CLOSE_AUTHORITY", level: "LOW", subject: "mint", detail: `${ext.authority.toBase58()} can close the mint at zero supply and re-create it with different extensions.` });
      }
      return;
    case "ConfidentialTransferMint":
      add({ id: "CONFIDENTIAL_TRANSFER", level: "LOW", subject: "mint", detail: "The mint supports confidential (hidden-amount) transfers." });
      return;
    case "InterestBearingConfig":
    case "ScaledUiAmountConfig":
      add({ id: "UI_AMOUNT_ADJUSTED", level: "MEDIUM", subject: "mint", detail: `${ext.name}: the displayed amount differs from the raw amount, and an authority can change the ratio.` });
      return;
    case "MetadataPointer":
      if ("metadataAddress" in ext && ext.metadataAddress && !ext.metadataAddress.equals(mint)) {
        add({
          id: "EXTERNAL_METADATA",
          level: "MEDIUM",
          subject: "mint",
          detail: `The mint's name and symbol live in another account (${ext.metadataAddress.toBase58()}), which this lane does not read, so a look-alike name there goes unchecked.`,
        });
      }
      return;
    case "TokenMetadata":
      if ("symbol" in ext) {
        const name = cleanText(ext.tokenName, 64) ?? "";
        const symbol = cleanText(ext.symbol, 64) ?? "";
        if (!ext.mint.equals(mint)) {
          add({ id: "METADATA_MISMATCH", level: "HIGH", subject: "mint", detail: `The mint's metadata says it belongs to ${ext.mint.toBase58()}.` });
        }
        if (!isKnown && looksLikeUsdc(name, symbol)) {
          add({
            id: "SPOOFED_METADATA",
            level: "HIGH",
            subject: "mint",
            detail: `Metadata calls it "${name}" / "${symbol}", but it is not the canonical USDC mint.`,
            data: { name, symbol },
          });
        }
      }
      return;
    default:
      return;
  }
}

// Letters from other scripts that render like the Latin ones in "USD Coin".
// Not the full Unicode confusables table: enough for this one name.
const CONFUSABLE: Record<string, string> = {
  "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "Х": "X", "Ԁ": "D",
  "а": "a", "с": "c", "е": "e", "і": "i", "о": "o", "р": "p", "ѕ": "s", "х": "x", "ԁ": "d", "ս": "u", "υ": "u", "ν": "v",
  "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "ο": "o", "ϲ": "c", "Ϲ": "C",
  "Ꮪ": "S", "Ꭰ": "D", "Ꮯ": "C", "ᑌ": "U", "Ⅽ": "C", "Ⅾ": "D", "ⅽ": "c", "ⅾ": "d",
};

function looksLikeUsdc(name: string, symbol: string): boolean {
  const squash = (s: string) =>
    Array.from(s.normalize("NFKC"))
      .map((c) => CONFUSABLE[c] ?? c)
      .join("")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "");
  const n = squash(name);
  const s = squash(symbol);
  return s.includes("USDC") || n.includes("USDC") || n.includes("USDCOIN");
}

// ---- helpers ----

function nameOf(id: PublicKey, withParens = true): string {
  const k = knownProgram(id);
  if (!k) return "";
  return withParens ? ` (${k.name})` : k.name;
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function uniqueKeys(keys: PublicKey[]): PublicKey[] {
  const seen = new Set<string>();
  return keys.filter((k) => {
    const s = k.toBase58();
    if (seen.has(s)) return false;
    seen.add(s);
    return true;
  });
}

function summarize(out: Inspection): string {
  const top = out.facts.filter((f) => f.level === out.level);
  if (out.level !== "LOW") return top.map((f) => f.detail).join(" ");
  const main = out.facts.find((f) =>
    ["WALLET", "SYSTEM_ACCOUNT_WITH_DATA", "PROGRAM_CONTROLLED", "OFF_CURVE_RECIPIENT"].includes(f.id)
  );
  const program = out.facts.find((f) => f.id === "IMMUTABLE_PROGRAM");
  const destinationClean = out.destination?.exists && !out.facts.some((f) => f.subject === "destination");
  return [main?.detail, program?.detail, destinationClean ? "Its USDC account is clean." : null]
    .filter(Boolean)
    .join(" ");
}

import * as anchor from "@anchor-lang/core";
import { BN, Program } from "@anchor-lang/core";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
} from "@solana/web3.js";
import { expect } from "chai";
import { readFileSync } from "fs";

import idl from "../target/idl/aegis_guard.json";
import { AegisGuard } from "../target/types/aegis_guard";

/** Devnet USDC. Tests put a classic 6-decimal mint at this address. */
export const USDC = new PublicKey("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
export const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111"
);
// anchor-lang event.rs: EVENT_IX_TAG, little endian
const EVENT_IX_TAG = Buffer.from([0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d]);

export type EntryKindName = "agent" | "deny" | "allow" | "blockprog" | "reporter";
const KIND_ARG: Record<EntryKindName, any> = {
  agent: { agent: {} },
  deny: { deny: {} },
  allow: { allow: {} },
  blockprog: { blockProgram: {} },
  reporter: { reporter: {} },
};

export const usdc = (n: number) => new BN(Math.round(n * 1_000_000));

export function loadKeypair(path: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, "utf8"))));
}

export function setup() {
  const env = anchor.AnchorProvider.env();
  const connection = new Connection(env.connection.rpcEndpoint, "confirmed");
  const provider = new anchor.AnchorProvider(connection, env.wallet, {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });
  anchor.setProvider(provider);
  const program = new Program<AegisGuard>(idl as AegisGuard, provider);
  return new Guard(program, provider);
}

export class Guard {
  readonly connection: Connection;
  readonly programId: PublicKey;
  readonly config: PublicKey;
  readonly audit: PublicKey;

  constructor(
    readonly program: Program<AegisGuard>,
    readonly provider: anchor.AnchorProvider
  ) {
    this.connection = provider.connection;
    this.programId = program.programId;
    this.config = this.pda([Buffer.from("config")]);
    this.audit = this.pda([Buffer.from("audit"), this.config.toBuffer()]);
  }

  pda(seeds: Buffer[]): PublicKey {
    return PublicKey.findProgramAddressSync(seeds, this.programId)[0];
  }

  entryPda(kind: EntryKindName, key: PublicKey): PublicKey {
    return this.pda([Buffer.from(kind), this.config.toBuffer(), key.toBuffer()]);
  }

  statsPda(recipient: PublicKey): PublicKey {
    return this.pda([Buffer.from("paid"), this.config.toBuffer(), recipient.toBuffer()]);
  }

  get programData(): PublicKey {
    return PublicKey.findProgramAddressSync(
      [this.programId.toBuffer()],
      BPF_LOADER_UPGRADEABLE
    )[0];
  }

  async airdrop(to: PublicKey, sol = 5) {
    const sig = await this.connection.requestAirdrop(to, sol * LAMPORTS_PER_SOL);
    const bh = await this.connection.getLatestBlockhash();
    await this.connection.confirmTransaction({ signature: sig, ...bh }, "confirmed");
  }

  async fundedKeypair(sol = 5): Promise<Keypair> {
    const kp = Keypair.generate();
    await this.airdrop(kp.publicKey, sol);
    return kp;
  }

  /** Send lamports to an address without creating program data there. */
  async prefund(address: PublicKey, lamports = 10_000_000) {
    const tx = new anchor.web3.Transaction().add(
      SystemProgram.transfer({
        fromPubkey: this.provider.wallet.publicKey,
        toPubkey: address,
        lamports,
      })
    );
    await this.provider.sendAndConfirm(tx);
  }

  addEntry(owner: Keypair, kind: EntryKindName, key: PublicKey, controller = PublicKey.default) {
    return this.program.methods
      .addEntry(KIND_ARG[kind], key, controller)
      .accountsPartial({
        owner: owner.publicKey,
        config: this.config,
        entry: this.entryPda(kind, key),
      })
      .signers([owner])
      .rpc();
  }

  removeEntry(owner: Keypair, kind: EntryKindName, key: PublicKey) {
    return this.program.methods
      .removeEntry(KIND_ARG[kind], key)
      .accountsPartial({
        owner: owner.publicKey,
        config: this.config,
        entry: this.entryPda(kind, key),
      })
      .signers([owner])
      .rpc();
  }

  async isEntry(kind: EntryKindName, key: PublicKey): Promise<boolean> {
    const info = await this.connection.getAccountInfo(this.entryPda(kind, key));
    return info !== null && info.owner.equals(this.programId);
  }

  /** The policy accounts `guarded_pay` and `assess` need, derived like a client would. */
  async policyAccounts(recipient: PublicKey, destination: PublicKey) {
    const info = await this.connection.getAccountInfo(recipient);
    const owner = info ? info.owner : SystemProgram.programId;
    const allowEntry = this.entryPda("allow", recipient);
    let blockprogController: PublicKey | null = null;
    const allowInfo = await this.connection.getAccountInfo(allowEntry);
    if (allowInfo && allowInfo.owner.equals(this.programId)) {
      const entry = this.program.coder.accounts.decode("entry", allowInfo.data);
      if (!entry.controller.equals(PublicKey.default)) {
        blockprogController = this.entryPda("blockprog", entry.controller);
      }
    }
    return {
      recipient,
      destination,
      denyEntry: this.entryPda("deny", recipient),
      allowEntry,
      blockprogOwner: this.entryPda("blockprog", owner),
      blockprogController,
    };
  }

  async payIx(agent: Keypair, recipient: PublicKey, destination: PublicKey, amount: BN, overrides: object = {}) {
    const cfg = await this.program.account.config.fetch(this.config);
    return this.program.methods.guardedPay(amount).accountsPartial({
      agent: agent.publicKey,
      agentEntry: this.entryPda("agent", agent.publicKey),
      config: this.config,
      vault: cfg.vault,
      mint: cfg.mint,
      stats: this.statsPda(recipient),
      ...(await this.policyAccounts(recipient, destination)),
      ...overrides,
    });
  }

  async pay(agent: Keypair, recipient: PublicKey, destination: PublicKey, amount: BN, overrides: object = {}) {
    const m = await this.payIx(agent, recipient, destination, amount, overrides);
    return m.signers([agent]).rpc();
  }

  async assess(recipient: PublicKey, destination: PublicKey, amount: BN, overrides: object = {}) {
    const a = await this.program.methods
      .assess(amount)
      .accountsPartial({
        config: this.config,
        ...(await this.policyAccounts(recipient, destination)),
        ...overrides,
      })
      .view();
    return {
      verdict: Object.keys(a.verdict)[0],
      reason: Object.keys(a.reason)[0],
      day: a.day as BN,
      spentToday: a.spentToday as BN,
      dailyLimit: a.dailyLimit as BN,
    };
  }

  logRefusal(
    reporter: Keypair,
    args: { recipient?: PublicKey | null; amount?: BN; verdict?: any; code?: string; reason?: string }
  ) {
    return this.program.methods
      .logRefusal(
        args.recipient ?? null,
        args.amount ?? new BN(0),
        args.verdict ?? { block: {} },
        args.code ?? "DENYLISTED",
        args.reason ?? "recipient denylisted"
      )
      .accountsPartial({
        reporter: reporter.publicKey,
        reporterEntry: this.entryPda("reporter", reporter.publicKey),
        config: this.config,
        audit: this.audit,
      })
      .signers([reporter]);
  }

  /** Decode self-CPI events (`emit_cpi!`) from a landed transaction. */
  async cpiEvents(signature: string) {
    let tx = null;
    for (let i = 0; i < 20 && !tx; i++) {
      tx = await this.connection.getTransaction(signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      if (!tx) await new Promise((r) => setTimeout(r, 250));
    }
    if (!tx) throw new Error(`transaction ${signature} not found`);
    const keys = tx.transaction.message.getAccountKeys().staticAccountKeys;
    const out: { name: string; data: any }[] = [];
    for (const inner of tx.meta?.innerInstructions ?? []) {
      for (const ix of inner.instructions) {
        if (!keys[ix.programIdIndex].equals(this.programId)) continue;
        const data = Buffer.from(anchor.utils.bytes.bs58.decode(ix.data));
        if (!data.subarray(0, 8).equals(EVENT_IX_TAG)) continue;
        const ev = this.program.coder.events.decode(data.subarray(8).toString("base64"));
        if (ev) out.push(ev);
      }
    }
    return out;
  }
}

let shared: Promise<{ owner: Keypair; agent: Keypair }> | null = null;

/** The owner and agent keys, created once per test run and shared by every suite. */
export function sharedKeys(g: Guard): Promise<{ owner: Keypair; agent: Keypair }> {
  if (!shared) {
    shared = (async () => {
      const [owner, agent] = await Promise.all([g.fundedKeypair(), g.fundedKeypair()]);
      return { owner, agent };
    })();
  }
  return shared;
}

/** Assert the promise rejects and the error (code, message or logs) names `name`. */
export async function expectError(p: Promise<unknown>, name: string) {
  let err: any;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err, `expected ${name}, but it succeeded`).to.not.equal(undefined);
  const text = [
    err?.error?.errorCode?.code,
    err?.message,
    ...(err?.logs ?? []),
    ...(err?.transactionLogs ?? []),
  ]
    .filter(Boolean)
    .join("\n");
  expect(text, text).to.include(name);
}

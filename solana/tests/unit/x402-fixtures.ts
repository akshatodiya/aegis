// A scripted chain for the x402 rail: the lane FakeChain for account reads,
// plus a genesis hash, a set of current blockhashes and a simulator. The
// default simulator really reads the transaction it is handed and moves the
// balances it would move, so a well-formed payment simulates cleanly and a
// test only overrides it to lie.
import { ComputeBudgetProgram, Keypair, MessageV0, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import { createTransferCheckedInstruction } from "@solana/spl-token";

import { DEVNET_GENESIS_HASH, MEMO_PROGRAM, TOKEN_PROGRAM, USDC_MINT } from "../../src/config";
import { associatedTokenAddress } from "../../src/guard/layout";
import { SimulationResult, SvmRpc } from "../../src/x402/rpc";
import { decodeTransaction } from "../../src/x402/wire";
import { FakeChain, key, tokenAccountBytes } from "./fixtures";

export class FakeRpc implements SvmRpc {
  genesis = DEVNET_GENESIS_HASH;
  readonly valid = new Set<string>();
  failing: Partial<Record<"genesis" | "blockhash" | "simulate", boolean>> = {};
  /** Replace to make the simulator lie. Receives the honest result. */
  tamper: ((honest: SimulationResult) => SimulationResult) | null = null;
  simulated: Uint8Array[] = [];

  constructor(readonly reader: FakeChain) {}

  async genesisHash() {
    if (this.failing.genesis) throw new Error("429 Too Many Requests");
    return this.genesis;
  }

  async latestBlockhash() {
    const blockhash = key().toBase58();
    this.valid.add(blockhash);
    return { blockhash, lastValidBlockHeight: 1000 };
  }

  async isBlockhashValid(blockhash: string) {
    if (this.failing.blockhash) throw new Error("429 Too Many Requests");
    return this.valid.has(blockhash);
  }

  async simulate(wire: Uint8Array): Promise<SimulationResult> {
    if (this.failing.simulate) throw new Error("429 Too Many Requests");
    this.simulated.push(wire);
    const honest = this.honest(wire);
    return this.tamper ? this.tamper(honest) : honest;
  }

  /** Applies the transaction's TransferChecked to the fake chain's balances, without saving. */
  private honest(wire: Uint8Array): SimulationResult {
    const { message } = decodeTransaction(wire);
    const keys = message.staticKeys;
    const balances = keys.map(() => 0);
    const pre: SimulationResult["preTokenBalances"] = [];
    const post: SimulationResult["postTokenBalances"] = [];
    let err: unknown = null;
    const moved = new Map<number, bigint>();
    for (const ix of message.instructions) {
      const program = keys[ix.programIdIndex];
      if (program.equals(TOKEN_PROGRAM) && ix.data[0] === 12) {
        const amount = Buffer.from(ix.data).readBigUInt64LE(1);
        const [src, , dst] = ix.accountIndexes;
        moved.set(src, (moved.get(src) ?? 0n) - amount);
        moved.set(dst, (moved.get(dst) ?? 0n) + amount);
      }
    }
    keys.forEach((k, i) => {
      const acct = this.reader.accounts.get(k.toBase58());
      if (!acct || !acct.owner.equals(TOKEN_PROGRAM) || acct.data.length !== 165) return;
      const mint = new PublicKey(acct.data.subarray(0, 32)).toBase58();
      const owner = new PublicKey(acct.data.subarray(32, 64)).toBase58();
      const before = acct.data.readBigUInt64LE(64);
      const after = before + (moved.get(i) ?? 0n);
      if (after < 0n) err = { InstructionError: [2, { Custom: 1 }] };
      pre.push({ accountIndex: i, mint, owner, amount: before.toString() });
      post.push({ accountIndex: i, mint, owner, amount: after.toString() });
    });
    return {
      err,
      unitsConsumed: err ? 3000 : 13180,
      preBalances: balances,
      postBalances: [...balances],
      preTokenBalances: err ? null : pre,
      postTokenBalances: err ? null : post,
      logs: [],
    };
  }
}

/** A funded x402 wallet (0 SOL, a USDC account) and a payee with a clean USDC account. */
export function x402World(o: { balance?: bigint } = {}) {
  const chain = new FakeChain();
  const rpc = new FakeRpc(chain);
  const us = Keypair.generate();
  const feePayer = key();
  const payTo = key();
  const source = associatedTokenAddress(us.publicKey, USDC_MINT);
  const destination = associatedTokenAddress(payTo, USDC_MINT);
  chain.set(source, TOKEN_PROGRAM, tokenAccountBytes({ owner: us.publicKey, amount: o.balance ?? 10_000_000n }));
  chain.set(destination, TOKEN_PROGRAM, tokenAccountBytes({ owner: payTo }));
  return { chain, rpc, us, feePayer, payTo, source, destination };
}

export interface PaymentParts {
  feePayer: PublicKey;
  us: PublicKey;
  payTo?: PublicKey;
  destination?: PublicKey;
  source?: PublicKey;
  amount?: bigint;
  mint?: PublicKey;
  decimals?: number;
  memo?: string | Buffer;
  units?: number;
  microLamports?: number | bigint;
  blockhash: string;
  tokenProgram?: PublicKey;
}

/** The four payment instructions, as the x402 exact client builds them. */
export function paymentInstructions(p: PaymentParts): TransactionInstruction[] {
  const mint = p.mint ?? USDC_MINT;
  const source = p.source ?? associatedTokenAddress(p.us, mint);
  const destination = p.destination ?? associatedTokenAddress(p.payTo!, mint);
  const transfer = createTransferCheckedInstruction(source, mint, destination, p.us, p.amount ?? 1_000_000n, p.decimals ?? 6, [], p.tokenProgram ?? TOKEN_PROGRAM);
  return [
    ComputeBudgetProgram.setComputeUnitLimit({ units: p.units ?? 20_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: p.microLamports ?? 1 }),
    transfer,
    new TransactionInstruction({ programId: MEMO_PROGRAM, keys: [], data: Buffer.from(p.memo ?? "0123456789abcdef0123456789abcdef") }),
  ];
}

export function compile(feePayer: PublicKey, blockhash: string, instructions: TransactionInstruction[]): Uint8Array {
  return MessageV0.compile({ payerKey: feePayer, recentBlockhash: blockhash, instructions }).serialize();
}

export function paymentMessage(p: PaymentParts): Uint8Array {
  return compile(p.feePayer, p.blockhash, paymentInstructions(p));
}

export { SystemProgram };

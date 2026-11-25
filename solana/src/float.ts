// The two floats, kept thin on purpose.
//
//  - The x402 float: the USDC the x402 wallet pays from. x402 payments never
//    pass the guard, so the float's size is the most a hijacked x402 wallet can
//    lose. It is refilled only through `guarded_pay`, so every refill draws on
//    the guard's daily cap: the cap governs x402 spend too, one refill at a
//    time. The x402 wallet itself holds 0 SOL; the facilitator pays fees.
//  - The agent's SOL: fees and rent for `guarded_pay` and receipts. The guard
//    can't meter it (fees are charged before any instruction runs, even on a
//    failed transaction), so a large balance is exposure, and it is reported.
//
// Refill rule (both): nothing at or above `min`; below it, back up to `target`.
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";

import { TOKEN_ACCOUNT_LEN, decodeTokenAccount } from "./chain/decode";
import { TOKEN_PROGRAM } from "./config";
import { GuardClient, SendOutcome } from "./guard/client";
import { associatedTokenAddress } from "./guard/layout";
import { formatUnits } from "./units";

export function floatPlan({ balance, target, min }: { balance: bigint; target: bigint; min: bigint }): { topUp: boolean; amount: bigint } {
  if (min > target) throw new Error(`float min (${min}) cannot exceed target (${target})`);
  if (balance >= min) return { topUp: false, amount: 0n };
  return { topUp: true, amount: target - balance };
}

/** floatPlan for SOL, plus how far above the intended float the wallet sits: the loss ceiling if its key leaks. */
export function gasFloatPlan({ balance, target, min }: { balance: bigint; target: bigint; min: bigint }): { topUp: boolean; amount: bigint; exposure: bigint } {
  if (min > target) throw new Error(`gas float min (${min}) cannot exceed target (${target})`);
  if (balance > target) return { topUp: false, amount: 0n, exposure: balance - target };
  if (balance >= min) return { topUp: false, amount: 0n, exposure: 0n };
  return { topUp: true, amount: target - balance, exposure: 0n };
}

export interface FloatOutcome {
  toppedUp: boolean;
  balance: bigint;
  funded: bigint;
  pay?: SendOutcome;
  messages: string[];
}

/**
 * Keeps the x402 wallet's USDC float at or above `min` by refilling it to
 * `target` through `guarded_pay`. `target` must not exceed the daily cap, so one
 * drained float can never exceed a day's bound. Amounts are base units.
 */
export async function ensureFloat(
  client: GuardClient,
  agent: Keypair,
  wallet: PublicKey,
  { target, min = target }: { target: bigint; min?: bigint }
): Promise<FloatOutcome> {
  const messages: string[] = [];
  const cfg = await client.config();
  if (!cfg) throw new Error(`aegis_guard at ${client.programId.toBase58()} is not initialized`);
  if (cfg.dailyLimit === 0n) throw new Error("ensureFloat: the guard's daily limit is 0 (frozen), so the float can't be refilled");
  if (target > cfg.dailyLimit) {
    throw new Error(`ensureFloat: target ${formatUnits(target)} USDC exceeds the daily limit ${formatUnits(cfg.dailyLimit)}; one drained float could then exceed a day's bound`);
  }
  const ata = associatedTokenAddress(wallet, cfg.mint);
  const [acct] = await client.reader.getAccounts([ata]);
  // Only a real token account counts; lamports alone at the address are "missing".
  const token = acct && acct.owner.equals(TOKEN_PROGRAM) && acct.data.length === TOKEN_ACCOUNT_LEN ? decodeTokenAccount(acct.data) : null;
  if (token) {
    if (!token.mint.equals(cfg.mint)) throw new Error(`ensureFloat: the float account ${ata.toBase58()} holds another mint (${token.mint.toBase58()})`);
    if (!token.owner.equals(wallet)) throw new Error(`ensureFloat: the float account ${ata.toBase58()} was reassigned to ${token.owner.toBase58()}; the wallet cannot spend it`);
    if (token.state === "frozen") throw new Error(`ensureFloat: the float account ${ata.toBase58()} is frozen; the wallet cannot spend it`);
    if (token.state !== "initialized") throw new Error(`ensureFloat: the float account ${ata.toBase58()} is not initialized`);
  }
  const balance = token?.amount ?? 0n;
  const plan = floatPlan({ balance, target, min });
  if (!plan.topUp) {
    messages.push(`x402 float holds ${formatUnits(balance)} USDC, at or above ${formatUnits(min)}: no refill.`);
    return { toppedUp: false, balance, funded: 0n, messages };
  }
  if (!token) {
    const made = await client.ensureRecipientAta(agent, wallet);
    messages.push(`created the float's USDC account ${made.address.toBase58()}.`);
  }
  messages.push(`x402 float holds ${formatUnits(balance)} USDC, below ${formatUnits(min)}: refilling ${formatUnits(plan.amount)} through the guard.`);
  const pay = await client.guardedPay(agent, wallet, plan.amount);
  messages.push(pay.ok ? `refilled: ${pay.signature}` : `refill not done (${pay.landed === null ? "could not tell whether it landed" : pay.code ?? "failed"}): ${pay.error}`);
  return { toppedUp: pay.ok, balance, funded: pay.ok ? plan.amount : 0n, pay, messages };
}

/** Where the agent's SOL stands against its intended float. `target`/`min` in lamports. */
export async function checkGasFloat(connection: Connection, who: PublicKey, { target, min = target }: { target: bigint; min?: bigint }) {
  const balance = BigInt(await connection.getBalance(who, "confirmed"));
  const plan = gasFloatPlan({ balance, target, min });
  const sol = (n: bigint) => (Number(n) / LAMPORTS_PER_SOL).toString();
  const message = plan.topUp
    ? `agent SOL ${sol(balance)} is below ${sol(min)}: top it up to ${sol(target)} (fees and rent).`
    : plan.exposure > 0n
      ? `agent SOL ${sol(balance)} is ${sol(plan.exposure)} above the ${sol(target)} float: that surplus is what a hijacked agent key can burn on fees, and no guard rule can stop it.`
      : `agent SOL ${sol(balance)} is within its float.`;
  return { balance, ...plan, message };
}

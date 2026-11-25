// USDC amounts without floats. The lanes and the CLI take decimal USDC ("12.5");
// the chain takes base units (12_500_000n). Converting through a string keeps
// 0.1 + 0.2 out of anything that moves money.
import { USDC_DECIMALS } from "./config";

const U64_MAX = (1n << 64n) - 1n;

/** "12.5" or 12.5 -> 12_500_000n. Throws on anything that isn't a non-negative decimal that fits in u64. */
export function toBaseUnits(amount: string | number | bigint, decimals = USDC_DECIMALS): bigint {
  if (typeof amount === "bigint") throw new Error("pass bigint base units directly, not to toBaseUnits");
  const text = typeof amount === "number" ? numberToPlain(amount) : amount.trim();
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) throw new Error(`not a non-negative decimal amount: ${JSON.stringify(amount)}`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`more than ${decimals} decimal places: ${text}`);
  const units = BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((frac + "0".repeat(decimals)).slice(0, decimals) || "0");
  if (units > U64_MAX) throw new Error(`amount does not fit in u64: ${text}`);
  return units;
}

function numberToPlain(n: number): string {
  if (!Number.isFinite(n) || n < 0) throw new Error(`not a non-negative finite amount: ${n}`);
  // toString gives exponents for tiny or huge numbers; toFixed(20) avoids them
  // but invents digits, so only use it when toString would use an exponent.
  const s = n.toString();
  if (!/e/i.test(s)) return s;
  return n.toFixed(20).replace(/\.?0+$/, "");
}

/** 12_500_000n -> "12.5" */
export function formatUnits(units: bigint, decimals = USDC_DECIMALS): string {
  const neg = units < 0n;
  const abs = neg ? -units : units;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = (abs % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? `.${frac}` : ""}`;
}

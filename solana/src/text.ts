// Cleaning text a counterparty wrote: token names and symbols now, the seller's
// resource text and memo when the x402 rail lands. Ported from the EVM build's
// cleanText, unchanged in behavior.
//
//  - control bytes become spaces, so an ANSI escape can't repaint a terminal and
//    "a<ESC>b" can't close up into a word nobody sent;
//  - format and default-ignorable characters go, matched by Unicode property:
//    bidi controls, zero widths, the U+E0000 tag block, variation selectors
//    (which can carry a byte each), and the blank Hangul fillers;
//  - whitespace collapses to one line;
//  - the result is capped by code point.
// This defangs the formatting, not the meaning: the text can still lie.
export function cleanText(value: unknown, limit: number): string | null {
  if (typeof value !== "string") return null;
  const flat = value
    .replace(/\p{Cc}/gu, " ")
    .replace(/[\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!flat) return null;
  const chars = Array.from(flat);
  return chars.length <= limit ? flat : `${chars.slice(0, limit - 3).join("")}...`;
}

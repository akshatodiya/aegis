# Aegis threat model

What Aegis stops, what it doesn't, and where the trust actually sits. Every claim
here should be reproducible against the deployed contracts on Arc testnet.

Short version: Aegis bounds what a compromised agent can *move*. It doesn't bound
what a compromised agent can *burn*, and on Arc those are the same asset.

## The attacker

The agent is the untrusted party. Assume its key is leaked, its prompt is
poisoned, or its tool output is attacker-controlled. So the attacker can make it
sign anything and call anything, with any calldata, at any gas price.

What the attacker doesn't have: the treasury key, the guard owner key, or the
x402 signing key. If any of those leak, Aegis is out of the picture.

## Two rails, two enforcement points

One policy engine, two payment rails, and the place it's enforced is genuinely
different on each. That difference matters more than the shared policy does.

**Treasury rail.** `AegisGuard.guardedPay` on Arc. The treasury holds the USDC
and approves only the guard. Agents are whitelisted to *trigger* payments but
never hold the funds. `assess()` runs inside the transfer in the same call, so
there's no window between the check and the move, and no TOCTOU gap where a
recipient swaps its code in between. A hijacked agent that calls the contract
directly still reverts on-chain. This is the strong rail: the enforcement is a
contract, not a convention.

**x402 rail.** EIP-3009 `transferWithAuthorization`, signed off-mempool and
settled by a facilitator. The guard isn't in the path at all, so it can't be the
enforcement point. That job falls to the wrapped signer: Aegis wraps
`signTypedData` and refuses to sign what it wouldn't approve. The fetch wrapper
decides (price, registry, domain pinning, per-payment cap) and the signer
enforces. This rail is only as strong as the process holding the signing key. If
the attacker gets that key directly, there's no second line.

## What Aegis stops

- A hijacked agent calling `guardedPay` against a flagged recipient. Reverts
  on-chain, verifiable on arcscan.
- Denylisted recipients, plus byte-identical redeploys in one write via the
  blocked-codehash switch. Its reach is narrower than "family" suggests, though:
  it matches the exact runtime artifact, solc metadata trailer and all.
  Recompiling the same source under a different compiler patch, or with one extra
  comment, changes that trailer and so the hash. It kills copies. Anything that
  escapes still lands on the unvetted-contract Review gate.
- Contract recipients nobody vetted. Those get Review instead of Pay, including
  EIP-7702 delegated EOAs, which carry code and so are treated as must-be-vetted.
- Spend *rate* on the treasury rail, through the rolling daily cap. Chunking a
  payment hits the same wall, because the cap is accumulated state and not a
  per-transaction check.
- On the x402 rail: overpriced quotes, unknown payees, unpinned EIP-712 domains,
  anything over the per-payment cap. The signer refuses before a signature
  exists, so there's nothing for a facilitator to settle.
- Recipient bytecode carrying danger opcodes, minimal-proxy indirection, or a
  trailing blob pretending to be solc metadata (see below).

## What Aegis does not stop

A firewall that oversells its coverage is worse than one that admits its edges,
so:

**1. Gas, which on Arc is the same money.** Gas is USDC, and the EVM takes it
from the sender before `guardedPay`'s first opcode runs. There's no point in the
call where the contract could refuse, and no clawing it back afterwards, since a
revert doesn't refund gas already burnt.

It's worse than "a second pot we don't watch". Checked against Arc testnet across
several unrelated addresses: the ERC-20 at
`0x3600000000000000000000000000000000000000` is a 6-decimal *view over the native
balance*, not a separate ledger. `native / 10^12 == erc20` held exactly, every
time. One balance, two decimal views.

So any USDC the guard can move by `transferFrom`, the same key can also burn as
gas, uncapped, with no policy in the way. The daily limit governs one spending
mechanism over a balance a second, ungoverned one can drain.

That gap used to be total here, with `treasury`, `owner`, the agent and the gas
payer all the same EOA.

The fix isn't a float, it's **separating the keys**, and it's live now. The
treasury holds the funds and approves the guard; the agent is a different key
holding only enough to pay gas:

```
treasury  0xa410..9fD2   86.00 USDC, signs nothing after its one approve
agent     0x3C00..9Eca6   2.96 USDC, pays gas, calls guardedPay
```

The hot key a prompt injection can actually reach now holds about 3% of the
money. That ratio is the bound. No redeploy was needed, because `setTreasury` and
`setAgent` are independent on the deployed contract, and `npm run rotate-keys`
does the split. It refuses to repoint the treasury until that treasury has
approved the guard, so there's never a window where the guard can't pull.
Verified afterwards: a guarded payment debited the treasury, decremented its
allowance, and left the agent's balance down only by gas.

What it doesn't fix: the agent's own gas float is still burnable, and the owner
is still the same key as the agent (item 3). `.env.example` already made this
argument one rail over, about why `X402_PRIVATE_KEY` has to differ from
`PRIVATE_KEY`. Now it holds on both.

`checkGasFloat` in `src/guard.js` reports how far a wallet sits above its
intended float. It's advisory and can't be otherwise, since a native top-up isn't
an ERC-20 `transferFrom` and so can't be routed through `guardedPay` and metered
by the cap.

**2. The x402 float bounds loss rate, not total loss.** That wallet is a separate
key holding only a float, refilled only through `guardedPay`. A daily cap on
refills bounds how fast an attacker drains, not how much they eventually get if
nobody intervenes. The kill switch is the refill line: stop `ensureFloat`, rotate
the wallet, and total loss caps at the current float.

**3. Owner key compromise is total.** The owner sets the denylist, the allowlist,
the codehash blocks and the daily limit. Ownership transfer is two-step so a
fat-fingered address can't brick admin, but a stolen owner key rewrites the
policy. No timelock, no multisig.

**4. The daily cap allows about 2x in a burst.** It buckets by
`block.timestamp / 1 days`, so spending the full limit just before UTC midnight
and again just after moves 2x inside a short window. Fine for a per-day rate
bound; it matters more as the limit grows.

**5. The bytecode lane reads instructions, it doesn't execute them.** The
imprecision runs both ways and the two directions aren't equally acceptable:

- *Over-flagging:* an opcode being present doesn't mean it's reachable. That's
  deliberate, and the LLM second pass is there to clear the false alarms.
- *Under-flagging:* a jump target computed at runtime (push plus arithmetic)
  instead of pushed as a constant can still hide from the reachability check
  below. Known gap, not a solved problem.

**6. One of the three lanes is still a mock.** These used to be described as a
pair, which blurred two different things:

- *Bytecode* is real: live `eth_getCode` plus an opcode walk, on Arc.
- *Behavior* is real now too. It reads the guard's own `Paid` events for how many
  times a recipient has actually been paid, and answers in three states rather
  than two: never, N times, or "couldn't read". The third is never reported as
  the first. Its limit is recency: the public Arc gateways reject wide `getLogs`
  ranges, so it scans a 50k-block window and says "recent history". Full history
  needs an indexer. There isn't one, and none is implied.
- *Reputation* is still entirely a mock, two hardcoded maps that nothing writes
  to. No reputation database exists and none is claimed.

Don't confuse that mock with the guard's own on-chain lists. The denylist,
allowlist, codehash blocks and daily cap are real contract storage enforced
inside `guardedPay`. That's the contract doing its job, not the off-chain lane
having data behind it.

**7. Naming a Circle contract isn't vouching for it.** See below.

## Designs that were dropped on purpose

Each of these got built out on paper, attacked, and thrown away. They're here so
they read as decisions and not as things nobody considered.

**An on-chain gas-inclusive spend cap.** The obvious move on a chain where gas is
the guarded asset: measure gas inside `guardedPay`, convert native 18-decimal
USDC to the 6-decimal unit, book it against the daily cap. Two separate reasons
killed it.

- It can't do what it claims. The check runs after the gas is already spent, and
  reverting doesn't refund it. Worse, the revert unwinds the booking too, so the
  one case worth catching, a gas spend big enough to breach the cap, is exactly
  the case that records nothing.
- It manufactures a new attack. `dailyLimit` is shared across agents and
  `tx.gasprice` is chosen by the agent. Metering one into the other lets a single
  compromised agent book a huge synthetic spend and lock everyone else out of the
  day's budget, at no cost to itself beyond gas it was paying anyway. Clamping
  doesn't fix that, it just picks a point between "enforces nothing" and "still
  griefable".

It would also have broken something the contract currently guarantees: `assess()`
and `guardedPay` are the same code, so the preview and the binding check can't
disagree. A `view` call has no real execution trace to measure, so no version of
`assess()` could honestly preview a gas check.

The enforceable version of that goal is the gas float in item 1.

**Re-weighting SELFDESTRUCT down on Arc.** The premise was that Arc neutralises
the classic stranding honeypot, making the top danger weight stale Ethereum
intuition. It doesn't hold up. `guardedPay` never issues a CALL to the recipient;
it moves funds through `IERC20.transferFrom`, a storage credit inside the token
contract. Whether the chain reverts a non-zero CALL to a destroyed account has no
bearing on whether USDC credited there becomes unreachable. It does either way.
And the part of the premise that is true, EIP-6780, applies to every post-Dencun
chain including Sepolia, so it was never Arc-specific.

**Writing Circle's system contracts into the on-chain allowlist.** `guardedPay`
sends a bare `transferFrom` with no calldata, and none of those contracts are a
meaningful destination for one. Paying USDC *to* the USDC contract isn't a
payment, it's a mistake that strands the funds, and the unvetted-contract Review
gate should keep catching it. Allowlisting would have taken a speed bump off a
footgun.

The lane names them instead. Eight of the nine Circle system contracts on Arc
score MEDIUM for DELEGATECALL, correctly, because they really are proxies. So it
reports what the contract is and what the trust rests on:

- Permit2 is deployed deterministically and can't be upgraded. A genuine LOW.
- USDC, TokenMessengerV2, GatewayWallet, GatewayMinter and FxEscrow are
  upgradeable by Circle. The DELEGATECALL is expected there, and the logic really
  can change under you. Trusting them is a bet on Circle's admin keys. Reasonable
  bet, still a bet, and zeroing the score would have hidden it.

Arc also runs proxies at `0x3600...0001/0002/0003` that are deliberately absent
from the list. They answer neither `name()` nor `version()`, so there's no way to
identify them from chain state, and an entry we can't justify is worse than none.

## Found and fixed

The metadata trim used to trust the recipient's own trailing length field plus a
single `0xa2` marker byte to decide where to stop scanning. Both live in code the
recipient chooses, so a contract could declare its malicious tail to be
"metadata" and walk right past the lane. Two bytes turned a live, reachable
SELFDESTRUCT from HIGH/60 into LOW/0, reported as "no known danger opcodes":

```
0x6009560000000000a25bff0000000000   HIGH  60  SELFDESTRUCT
0x6009560000000000a25bff0000000006   LOW    0  (bypassed)
```

That's a false negative, and it's the one direction a firewall can't fail in. The
trim now needs the blob to be structurally valid CBOR accounting for every byte
up to the length field, and it won't cut a blob the code jumps into, which is
what catches an attacker who crafts valid CBOR instead. Both variants plus the
honest case are pinned in `test/bytecode.test.mjs`.

Real solc metadata still trims at exactly the right boundary, checked against the
deployed Arc USDC runtime and unchanged across all nine Circle system contracts.

Then the fix itself got attacked and turned out to have its own hole. The
reachability check only looked at `PUSH1` through `PUSH4`, so the same crafted
blob reached by a `PUSH5` carrying an identical zero-padded target sailed
through. No arithmetic needed, just a wider push:

```
PUSH1 0x0c ; JUMP           -> flagged, blob kept, SELFDESTRUCT scored
PUSH5 0x000000000c ; JUMP   -> not flagged, blob trimmed, contract reported LOW/0
```

Every width is read now, with the bytes above the low four required to be zero
for the value to be a plausible offset. The tests walk all 32 widths instead of
the one that got reported, plus a case asserting a genuine wide constant isn't
mistaken for a jump target.

The lesson is worth keeping. The first fix was written against the attack that
had been demonstrated, not the class it belonged to, and a narrow check that
happens to cover the proof of concept reads exactly like a correct one until
somebody widens the opcode.

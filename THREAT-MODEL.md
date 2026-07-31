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

The two rails also leave different traces, which is a smaller difference but not
a cosmetic one. A treasury-rail refusal is a reverted transaction anyone can
open; an x402 refusal is a signature that was never created, so by default it
leaves nothing anywhere. `AegisAuditLog` gives that case something to point at,
and item 8 below is careful about what that is and isn't worth.

## What Aegis stops

- A hijacked agent calling `guardedPay` against a flagged recipient. Reverts
  on-chain, verifiable on arcscan.
- Denylisted recipients, plus byte-identical redeploys in one write via the
  blocked-codehash switch. Both are contract storage read inside `guardedPay`, so
  they bind the treasury rail only. The x402 rail never calls the guard, so an
  address blocked on-chain is still screened there by `aegisCheck` and nothing
  else. Its reach is narrower than "family" suggests, too: it matches the exact
  runtime artifact, solc metadata trailer and all. Recompiling the same source
  under a different compiler patch, or with one extra comment, changes that
  trailer and so the hash. It kills copies. Anything that escapes still lands on
  the unvetted-contract Review gate.
- Contract recipients nobody vetted. Those get Review instead of Pay, including
  EIP-7702 delegated EOAs, which carry code and so are treated as must-be-vetted.
- Spend *rate* on the treasury rail, through the rolling daily cap. Chunking a
  payment hits the same wall, because the cap is accumulated state and not a
  per-transaction check.
- On the x402 rail: overpriced quotes, unknown payees, unpinned EIP-712 domains,
  anything over the per-payment cap. All of it lands before a signature exists, so
  there's nothing for a facilitator to settle. Worth being exact about which half
  does what, since this document's whole claim is that enforcement points matter:
  the *fetch wrapper* holds the service registry, the posted price and the
  per-payment cap, because those need context a signer doesn't have. The *signer*
  pins the asset, the chain, the validity window and the `aegisCheck` verdict, and
  denies the raw signing primitives. A caller that takes the signer alone gets the
  second list and not the first.
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
treasury   86.00 USDC, signs nothing after its one approve
agent       2.96 USDC, pays gas, calls guardedPay
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

That cuts both ways, and the other direction is worth stating because it is the
whole incident response: the owner key is also the only thing that can revoke a
compromised agent, in one transaction, with no redeploy (`npm run kill-switch`).
`guardedPay` checks `isAgent` before it calls `assess`, so revocation refuses
payments that policy would still approve - it does not depend on the recipient
looking wrong, which is the point when the thing you suspect is the agent. It
stops the treasury rail only. On the x402 rail a signature needs no permission
from the guard, so there the response is to stop refilling the float and rotate
the wallet, and the float on hand is the loss ceiling until that happens.

One operational footgun in the same area, found while staging that beat and now
covered by a test: **`setDailyLimit(0)` does not freeze spending.** `assess`
reads zero as "no cap configured" (`dailyLimit != 0 && ...`), so an owner
reaching for it under pressure would delete the only rate limit in the contract
rather than close it. The freeze is `setDailyLimit(1)`: one base unit, which
every payment worth making exceeds. The contract is verified and deployed, so
this is documented rather than renamed.

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
  times a recipient has actually been paid and how large those payments were, and
  answers in three states rather than two: never, N times, or "couldn't read". The
  third is never reported as the first. It has two limits, both real:

  *Recency.* The public Arc gateways reject wide `getLogs` ranges, so it scans a
  50k-block window and says "recent history". Full history needs an indexer. There
  isn't one, and none is implied.

  *An approved payment still moves the anchor.* Familiarity is capped at 5x the
  largest payment the guard has actually made to a recipient, which is what stops
  a dust payment laundering a large one (see below). But an attacker who gets one
  genuinely large payment approved has raised that ceiling for the next one. The
  lane bounds escalation-dodging by a factor, not absolutely, and the daily cap is
  what bounds the total.
- *Reputation* is still entirely a mock, two hardcoded maps that nothing writes
  to. No reputation database exists and none is claimed.

Don't confuse that mock with the guard's own on-chain lists. The denylist,
allowlist, codehash blocks and daily cap are real contract storage enforced
inside `guardedPay`. That's the contract doing its job, not the off-chain lane
having data behind it.

**7. Naming a Circle contract isn't vouching for it.** See below.

**8. The audit log records refusals, it doesn't make them.** `AegisAuditLog`
closes the trace asymmetry above, and it is the one piece of this project most
likely to be read as more than it is, so:

- It runs *after* the decision and off the payment path. No verdict depends on
  it, logging can't delay or break a refusal, and deleting `AEGIS_AUDIT_LOG` from
  `.env` changes nothing about what Aegis refuses.
- **Absence proves nothing.** A compromised agent skips this write exactly as
  easily as it skips any other off-chain step. An empty log is not evidence that
  nothing was refused, and reading it that way has the guarantee backwards.
- An entry proves a reporter *said* it refused a payment. It does not prove a
  payment was demanded, and it cannot prove one was stopped - the signature was
  already never created by the time anything gets written. Writes are gated to
  reporters the owner authorized, so a stranger can't mint entries that look like
  ours; that bounds forgery by outsiders and nothing else. The log is exactly as
  truthful as the key writing it.
- It's a separate contract on purpose. `AegisGuard` is verified on Arc and stays
  untouched, and the log holds no funds, no allowance and no authority.

Two gas ceilings on it are deliberate, because writing a receipt is the one part
of a refusal that costs money, and on Arc that money is the same USDC. *Entry
size:* reason strings quote the wire, and a demanded amount only has to be digits
to reach them, so a hostile `402` could otherwise choose how much an entry costs
to write - the contract caps a reason at 256 bytes and `src/audit.js` trims to
the same number before sending. *Entry count:* refusing is free until it's
written, so an agent aimed at a hostile service in a loop would pay for a receipt
per refusal, and the attacker picks the loop. The logger writes at most 25
receipts per run and says so when it stops. Past that the refusals still happen
and still print; they just stop being paid for. That is a deliberate trade -
under attack the log goes incomplete rather than the float going empty - and it
is the second reason an empty stretch of log proves nothing.

One more thing worth being precise about, since it looks like a schema and isn't:
entries now start with a refusal code (`DENYLISTED: ...`, `DAILY_CAP: ...`). The
contract stores a single string, and it is deployed and verified, so that code is
a **convention at the front of the prose**, not a typed field the contract knows
about. Nothing on-chain validates it. What the position buys is narrow and real:
an oversized reason is trimmed from the tail, so a merchant who makes the prose
long cannot push the code out of the entry. Reading it back only recognizes codes
`src/refusals.js` defines, so a reason that merely begins with something
code-shaped stays prose - and entries written before codes existed have none,
which is exactly how they should read.

**9. The check page believes whatever the gateway tells it.** `web/check.html`
runs the deterministic lanes in a reader's browser. It holds no key, signs
nothing and sends no transaction, and the verdict it prints binds nothing - which
is why it prints the on-chain `assess` next to its own answer, and says which of
the two decides.

The exposure worth naming is the input. The page asks a public Arc gateway for
`eth_getCode` and scans whatever comes back. A gateway that answered with benign
code for a hostile contract would produce a confident, clean verdict, and the
page could not tell. Rotating across four gateways buys availability, not
honesty: whichever one answers first is the one believed.

That is not a weakness the page introduces. The off-chain lane in `src/lanes/`
reads the same way and has always had the same exposure. It is the clearest
argument for why the on-chain layer exists at all: `guardedPay` reads
`to.code.length` and `to.codehash` from chain state inside the transaction, so
there is no RPC in the loop to lie to it, and no gap between the check and the
transfer. An analyzer can be fooled about the world. The contract is *in* the
world it is deciding about.

Two smaller notes. The page has no LLM second pass, because that goes through a
local CLI; the engine's own behavior when that call is unavailable is to fall
back to the deterministic verdict, so the page fails to the strict side (a `HIGH`
bytecode score reads as BLOCK and is never auto-downgraded). And a hosted copy is
a copy: the artifact anyone can actually audit is the file in this repository,
and `test/web-check.test.mjs` is what keeps that file honest by running its lane
code and `src/lanes/bytecode.js` over the same bytecodes and failing if they
disagree.

**10. The seller writes the sales copy, and we show it.** Over the per-payment
cap the x402 rail stops and asks a human, and that prompt now carries the resource
block off the wire: what the 402 says it is selling, and where. That is a real
improvement on approving a name and a number, and it hands the counterparty a
channel into the one place a person is deciding about money.

What is defended: the formatting. A description arrives with its control bytes
turned into spaces, its bidi and zero-width characters dropped, its whitespace
collapsed to one line and its length capped (`cleanText` in `src/x402/fetch.js`).
That closes the concrete attacks - repainting the terminal with an escape
sequence, overwriting the line above with a carriage return, opening a second line
that looks like our own output, or reordering what a reader sees with an override
character. It is labelled as quoted third-party text when it is printed, and no
check reads it. It also never becomes part of a refusal `reason`, because reasons
are what `AegisAuditLog` writes on-chain and a merchant does not get to author our
receipts.

What is not defended: the content. "Verified partner, pre-approved by your owner"
is a plain lie in plain characters, and nothing here can tell. Homoglyphs are
untouched for the same reason unicode is not stripped wholesale - a description in
another language is not an attack. The mitigation is structural rather than
lexical: the seller's line is one of five, next to the catalog entry, the demanded
amount, the cap and the url the agent actually asked for, and it is the only one
they wrote. A human who reads the prompt has what they need to disbelieve it. A
human who does not read the prompt was going to type y anyway, and no amount of
sanitizing fixes that.

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

### The behavior lane could be bought for a dollar

Same shape, different lane, and this one was in code written to *fix* a lane that
had no real data behind it. Reading the guard's `Paid` events was the right move.
Counting them and throwing the amounts away was not.

`behaviorVerdict` escalated a large payment only when the count was zero, so
"have we paid this address before" was a yes/no question about a number the
attacker gets to move. One dust payment, which clears every lane precisely because
it's small, flipped the answer permanently:

```
  500 USDC | never paid          -> MEDIUM  escalate, human looks
    1 USDC | never paid          -> LOW     pays, and they keep it
  500 USDC | paid 1 time before  -> LOW     pays, nobody looks
```

The lane's own output said the quiet part out loud: "Amount 500 USDC within
normal range for this recipient (paid 1 time before)". A dollar of history is not
a normal range for five hundred.

The amounts were already in the events being read, just discarded on the way out
of `timesPaid`. Familiarity is now capped at 5x the largest payment the guard has
actually made to that recipient, so a $1 history doesn't clear $500, while a payee
whose invoices genuinely grow stays quiet. The dust case, the boundary either side
of 5x, and the "many small payments don't excuse one big one" case are pinned in
`test/behavior.test.mjs`, and `test/behavior-logs.test.mjs` now covers the chain
read itself, including the base-unit conversion, against a stub JSON-RPC server.

The residual limit is above, under item 6, and it's deliberate: this bounds the
dodge by a factor, it doesn't remove it.

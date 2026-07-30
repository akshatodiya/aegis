# Aegis threat model

What Aegis stops, what it does not, and where the trust actually sits. Written
to be checkable: every claim here should be something you can reproduce against
the deployed contracts on Arc testnet, and every limitation is one we chose to
state rather than let a judge find.

The short version: Aegis bounds what a compromised agent can *move*. It does not
bound what a compromised agent can *burn*, and on Arc those are the same asset.

## The attacker

The agent is the untrusted party. Assume its key is leaked, its prompt is
poisoned, or its tool output is attacker controlled - the standard agent
compromise. The attacker can therefore make the agent sign anything and call
anything, with any calldata, at any gas price.

What the attacker does *not* have: the treasury key, the guard owner key, or the
x402 signing key. If any of those leak, Aegis is out of the picture. That is the
boundary, not a footnote.

## Two rails, two different enforcement points

Aegis runs one policy engine over two payment rails, and the enforcement point
is genuinely different on each. This matters more than the shared policy does.

**Treasury rail.** `AegisGuard.guardedPay` on Arc. The treasury holds the USDC
and approves only the guard contract. Agents are whitelisted to *trigger*
payments but never hold the funds. `assess()` runs inside the transfer in the
same call, so there is no window between the check and the move, and no TOCTOU
gap where a recipient swaps its code in between. A hijacked agent that calls the
contract directly still reverts on-chain. This is the strong rail: enforcement
is a contract, not a convention.

**x402 rail.** EIP-3009 `transferWithAuthorization`, signed off-mempool and
settled by a facilitator. The guard contract is not in the path at all, so it
cannot be the enforcement point. Enforcement is the wrapped signer: Aegis wraps
`signTypedData` and refuses to sign what it would not approve. The fetch wrapper
decides (price, registry, domain pinning, per-payment cap) and the signer
enforces. This rail is only as strong as the process holding the signing key.
If the attacker gets that key directly, there is no second line.

## What Aegis stops

- A hijacked agent calling `guardedPay` directly against a flagged recipient.
  Reverts on-chain, verifiable on arcscan.
- Denylisted recipients, and byte-identical redeploys in one write via the
  blocked codehash kill switch. Be precise about its reach: it matches the exact
  runtime artifact, solc metadata trailer included. Recompiling the same source
  with a different compiler patch version, or with one comment added, changes
  that trailer and therefore the hash. So it kills copies, not families, and the
  bar for escaping it is lower than "write a new contract". Anything that
  escapes still lands on the unvetted-contract Review gate.
- Contract recipients that were never vetted. They return Review, not Pay -
  including EIP-7702 delegated EOAs, which carry code and are treated as
  must-be-vetted rather than as plain wallets.
- Spend *rate* on the treasury rail, via the rolling daily cap. Splitting a
  payment into chunks hits the same wall, because the cap is real accumulated
  state and not a per-transaction check.
- On the x402 rail: overpriced quotes, unknown payees, unpinned EIP-712 domains,
  and anything over the per-payment cap. The signer refuses before a signature
  exists, so there is nothing for a facilitator to settle.
- Recipient bytecode carrying danger opcodes, minimal-proxy indirection, or a
  trailing blob that is pretending to be solc metadata (see below).

## What Aegis does not stop

Stated plainly, because a firewall that overstates its coverage is worse than
one that admits its edges.

**1. Gas, and the fact that on Arc it is the same money.** Gas is USDC, and the
EVM deducts it from the sender before `guardedPay`'s first opcode runs. There is
no point in the call where the contract could refuse, and no way to claw it back
afterwards, because a revert does not refund gas already burnt. So gas is
spendable value the guard structurally cannot reach.

It is worse than "a second pot we don't watch". Verified against Arc testnet
across several unrelated addresses: the ERC-20 at
`0x3600000000000000000000000000000000000000` is a 6-decimal *view over the
native balance*, not a separate ledger. For every address checked,
`native / 10^12 == erc20` exactly. One balance, two decimal views.

Which means: **any USDC the guard can move by `transferFrom`, the same key can
also burn as gas, with no cap and no policy in the way.** The daily limit
governs one spending mechanism over a balance that a second, ungoverned
mechanism can drain.

That gap used to be total here. `treasury`, `owner`, the whitelisted agent and
the gas payer were all one EOA, so the guard's 100 USDC daily cap governed a
balance that was 100% burnable as gas outside it.

The fix is not a float, it is **separating the keys**, and it is now applied on
the live deployment. The treasury holds the funds and approves the guard; the
agent is a different key holding only a gas float:

```
treasury  0xa410..9fD2   86.00 USDC, signs nothing after its one approve
agent     0x3C00..9Eca6   2.96 USDC, pays gas, calls guardedPay
```

The hot key that a prompt injection can actually reach now holds about 3% of the
money instead of all of it. That ratio is the bound. It needed no redeploy:
`setTreasury` and `setAgent` are independent on the deployed contract, and
`npm run rotate-keys` performs the split (refusing to repoint the treasury until
that treasury has approved the guard, so there is never a window where the guard
cannot pull). Verified end to end afterwards: a guarded payment debited the
treasury, decremented its allowance, and left the agent's balance touched only
for gas.

What this does NOT fix: the agent's own gas float is still burnable, and the
owner is still the same key as the agent (see item 3). This project made the
same argument one rail over, in `.env.example`, about why `X402_PRIVATE_KEY`
must differ from `PRIVATE_KEY`. It now applies on both rails.

`checkGasFloat` in `src/guard.js` reports how far a wallet sits above its
intended gas float. It is advisory and cannot be otherwise: a native top-up is
not an ERC-20 `transferFrom`, so unlike `ensureFloat` it cannot be routed
through `guardedPay` and metered by the cap. Thinning the gas balance is only
meaningful once the agent is not also the treasury.

**2. The x402 float bounds loss rate, not total loss.** The x402 wallet is a
separate key holding only a float, refilled only through `guardedPay`. A daily
cap on refills bounds how fast an attacker drains, not how much they eventually
get if nobody intervenes. The kill switch is the refill line: stop `ensureFloat`
and rotate the wallet, and total loss caps at the current float.

**3. Owner key compromise is total.** The guard owner sets the denylist, the
allowlist, the codehash blocks and the daily limit. Ownership transfer is
two-step so a fat-fingered address cannot brick admin, but a stolen owner key
rewrites the policy. There is no timelock and no multisig.

**4. The daily cap allows about 2x in a burst.** The cap buckets by
`block.timestamp / 1 days`, so spending the full limit just before UTC midnight
and again just after moves 2x the limit inside a short window. Accepted for a
per-day rate bound; it matters more the larger the limit gets.

**5. The bytecode lane reads instructions, it does not execute them.** Two
directions of imprecision, and they are not symmetric:

- *Over-flagging:* an opcode being present does not mean it is reachable. This is
  deliberate, and the LLM second pass exists to sort out the false alarms.
- *Under-flagging:* a jump target computed at runtime (push plus arithmetic)
  rather than pushed as a constant can still hide code from the reachability
  check described below. That is a known gap, not a solved problem.

**6. One of the three lanes is still a mock, and it is worth being exact about
which.** These used to be described as a pair, which blurred two different
things:

- *Bytecode* is real: live `eth_getCode` plus an opcode walk, on Arc.
- *Behavior* is now real too. It reads the guard's own `Paid` events and answers
  how many times this recipient has actually been paid. It returns three states,
  not two - never, N times, and "could not read" - and the third is never
  reported as the first. Its honest limit is recency, not truthfulness: the
  public Arc gateways reject wide `getLogs` ranges, so it scans a 50k-block
  window and says "recent history" rather than "never". Full history needs an
  indexer; there isn't one, and none is implied.
- *Reputation* is still entirely a mock: two hardcoded maps that nothing writes
  to. No reputation database exists and none is claimed.

Do not confuse the reputation lane with the guard's own on-chain lists. The
denylist, allowlist, codehash blocks and daily cap are genuine contract storage
and are enforced inside `guardedPay` - that is the contract doing its job, not
the off-chain lane having data behind it.

**7. Naming a Circle contract is not vouching for it.** See below.

## Decisions deliberately not taken

These were designed, attacked, and dropped. Recorded here so they read as
choices rather than as things nobody thought about.

**An on-chain gas-inclusive spend cap.** The obvious move on a chain where gas
is the guarded asset: measure gas inside `guardedPay`, convert native 18-decimal
USDC to the 6-decimal ERC-20 unit, book it against the daily cap. Dropped for
two independent reasons.

- It cannot do what it claims. The check would run after the gas was already
  spent, and reverting does not refund it. Worse, the revert unwinds the
  booking too, so the single case worth catching - a gas spend big enough to
  breach the cap - is the exact case that records nothing.
- It would manufacture a new attack. `dailyLimit` is a shared bucket across all
  agents, and `tx.gasprice` is chosen by the agent. Metering one into the other
  lets a single compromised agent book an enormous synthetic spend and lock
  every other agent out of the day's budget, at no cost to itself beyond gas it
  was paying anyway. A clamp does not fix this, it just picks a point between
  "enforces nothing" and "still griefable".

It would also have broken a property the contract currently guarantees: that
`assess()` and `guardedPay` are the same code, so the preview and the binding
check cannot disagree. A `view` call has no real execution trace to measure, so
no honest version of `assess()` can preview a gas check.

The enforceable version of the same goal is the gas float in item 1 above.

**Re-weighting SELFDESTRUCT down on Arc.** The premise was that Arc neutralises
the classic stranding honeypot, so scoring SELFDESTRUCT as the single highest
danger weight is stale Ethereum intuition. Dropped: `guardedPay` never issues a
CALL to the recipient, it moves funds through `IERC20.transferFrom`, which is a
storage credit inside the token contract. Whether the chain reverts a non-zero
CALL to a destroyed account has no bearing on whether USDC credited to that
address becomes unreachable. It does, either way. And the part of the premise
that is true, EIP-6780, applies to every post-Dencun chain including Sepolia, so
it was never Arc-specific in the first place.

**Writing Circle's system contracts into the on-chain allowlist.** `guardedPay`
sends a bare `transferFrom` with no calldata, and none of Circle's system
contracts are a meaningful destination for that. Paying USDC *to* the USDC
contract is not a payment, it is a mistake that strands the funds, and the
unvetted-contract Review gate should keep catching it. Allowlisting would have
removed a speed bump from a footgun.

The lane names them instead. Eight of the nine Circle system contracts on Arc
score MEDIUM for DELEGATECALL, correctly, because they really are proxies. So
Lane 1 reports what the contract is and what the trust rests on rather than
suppressing the score:

- Permit2 is deployed deterministically and is not upgradeable. A genuine LOW.
- USDC, TokenMessengerV2, GatewayWallet, GatewayMinter and FxEscrow are
  upgradeable by Circle. Their DELEGATECALL is expected, and their logic really
  can change under you. Trusting them is a bet on Circle's admin keys, which is
  a reasonable bet and still a bet. Zeroing the score would have hidden that.

Arc also runs proxies at `0x3600...0001/0002/0003` that are deliberately absent
from that list. They answer neither `name()` nor `version()`, so they cannot be
identified from chain state alone, and an entry that cannot be justified is
worse than no entry.

## Found and fixed

The metadata trim in the bytecode lane used to trust the recipient's own
trailing length field plus a single `0xa2` marker byte to decide where to stop
scanning. Both live in code the recipient chooses, so a contract could declare
its malicious tail to be "metadata" and walk past the lane. Two bytes turned a
live reachable SELFDESTRUCT from HIGH/60 into LOW/0, reported as "no known
danger opcodes":

```
0x6009560000000000a25bff0000000000   HIGH  60  SELFDESTRUCT
0x6009560000000000a25bff0000000006   LOW    0  (bypassed)
```

This was a false negative, which is the one direction a firewall cannot fail in.
The trim now requires the blob to be structurally valid CBOR that accounts for
every byte up to the length field, and refuses to cut a blob the code jumps
into, which is what catches an attacker who crafts valid CBOR instead. Both
variants and the honest case are locked in by `test/bytecode.test.mjs`.

Genuine solc metadata still trims at exactly the right boundary, verified
against the real deployed Arc USDC runtime and unchanged across all nine Circle
system contracts.

Then the fix itself was attacked, and it had a hole of its own. The reachability
check only evaluated `PUSH1` through `PUSH4`, so the same crafted blob reached by
a `PUSH5` carrying an identical zero-padded target walked straight through it -
no arithmetic required, just a wider push opcode:

```
PUSH1 0x0c ; JUMP  -> flagged, blob kept, SELFDESTRUCT scored
PUSH5 0x000000000c ; JUMP  -> not flagged, blob trimmed away, contract reported LOW/0
```

Every push width is now read, with the bytes above the low four required to be
zero for the value to be a plausible code offset. `test/bytecode.test.mjs` walks
all 32 widths rather than the one that was reported, plus a case asserting a
genuine wide constant is not mistaken for a jump target.

The general lesson is the one worth keeping: the first fix was written against
the attack that had been demonstrated, not against the class it belonged to. A
narrow check that happens to cover the proof of concept reads exactly like a
correct one until someone widens the opcode.

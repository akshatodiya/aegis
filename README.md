# Aegis

A firewall for AI agents that pay in USDC, built on [Arc](https://arc.network),
Circle's stablecoin L1 where USDC *is* the native gas token.

An agent about to move money is one bad address away from a drain. Aegis sits in
front of the payment, looks at *who is getting paid*, and answers one of three
things:

- **PAY** - looks safe, let it go
- **BLOCK** - dangerous, stop it
- **ASK_HUMAN** - not sure, get a person to look

The catch with agents is that the checker is only as good as its ability to *not
be skipped*. A prompt-injected agent will happily ignore an off-chain analyzer.
So Aegis enforces at **the point where a payment becomes irreversible**, and that
point is different for the two ways an agent spends:

- **the treasury rail** - the agent pays through an on-chain contract,
  `AegisGuard`. The policy runs *inside* the transfer, on-chain, atomically. A
  hijacked agent that skips every off-chain check and calls the contract directly
  still hits a wall: the payment reaches the chain and **reverts**.
- **the x402 rail** - the agent pays a service over HTTP using x402
  (EIP-3009 `transferWithAuthorization`). Nothing is broadcast - the agent
  *signs*, and a facilitator settles. There's no transaction to revert, so the
  enforcement point is **the signer**: Aegis wraps it, and a payment it doesn't
  approve is never signed.

Same policy engine, two enforcement points. That's the honest framing - Aegis
doesn't claim one magic on-chain gate; it claims that on *each* rail it sits at
the last place a payment can still be stopped.

## Live on Arc

Everything below is deployed and exercised on Arc testnet
(chain `5042002`, explorer [testnet.arcscan.app](https://testnet.arcscan.app)).

| What | Address / tx | |
|------|--------------|---|
| `AegisGuard` | [`0xb95f…728d`](https://testnet.arcscan.app/address/0xb95f9c997235150d5f43b7c05897bb8e0173728d) | the firewall contract - agents pay through it (treasury approves it, daily cap 100 USDC) |
| `HoneypotVault` | [`0x9a0d…de9c`](https://testnet.arcscan.app/address/0x9a0da68c0f9654bd7110e928f229b7c4c216de9c) | the demo villain (see below) |
| `AegisAuditLog` | [`0xbce4…7659`](https://testnet.arcscan.app/address/0xbce4621b1347940bf7930707f83c6a5d1e797659) | the x402 rail's receipts - records refusals, enforces nothing |

Four receipts a judge can open:

- **a hijacked agent tries to drain the treasury and the chain says no** -
  [reverted `guardedPay`](https://testnet.arcscan.app/tx/0xfe0434b5190fdda2d294296162903b13e0e78fb5717257b23e73160ceb5b8ade).
  This is the whole thesis in one transaction: the agent skipped Aegis entirely
  and called the contract directly, and the money still didn't move.
- **a payment that *was* allowed through** -
  [a guarded transfer that settled](https://testnet.arcscan.app/tx/0x6acc8c6c507c4f6ed155551d9e6bcf579facb49e017717199d8ac5f5b5337481)
  (this one tops up the x402 float wallet - see the x402 rail below).
- **a refusal on the rail where refusals leave no transaction** -
  [an x402 payment Aegis declined to sign](https://testnet.arcscan.app/tx/0xf116f20f87bd836cd6d77057790770e04c344bd91b748d5ac4a7865688de12c3),
  a merchant demanding 50x its posted price. Nothing was broadcast, because
  nothing was signed - so this entry is a receipt written afterwards, not the
  refusal itself. The difference matters and is spelled out below.
- **the owner shutting the agent off, live** -
  [`setAgent(agent, false)`](https://testnet.arcscan.app/tx/0xb426ad1fa66a9cc1eabd43234b2e6011739aebaba644dad8cb15688dcde38cba),
  and then [the same payment refused](https://testnet.arcscan.app/tx/0x34faa65566982338dadd69b8ef8bf2c48e0ddeeab2a254811e4700aa080cd73a)
  seconds later, to a recipient the guard still called clear. It burnt 24,259
  gas: it reverted on `guardedPay`'s first line, before policy was read at all.

And one thing to run rather than read:
**[check any address yourself](https://anon1one.github.io/aegis/web/check.html)**.
`web/check.html` is one static file that runs the deterministic lanes in your
browser against Arc's public RPC, and reads the deployed guard's own `assess`
next to its answer. No clone, no key, no backend, and nothing loaded from a CDN.
Paste the honeypot, or one of its clones, or USDC, and watch where the two layers
agree and where they don't. What it is and is not is on the page itself.

## How the decision is made

Three checks on the recipient, mapped onto on-chain state in the contract:

| Lane | Where it lives | What it looks at |
|------|----------------|------------------|
| Bytecode | off-chain scan + on-chain code check | reads the recipient's EVM code (live `eth_getCode` on Arc) and flags traps like `SELFDESTRUCT`, `DELEGATECALL`, `CREATE2`, `tx.origin` - and won't let a recipient hide code from the scan behind a faked metadata trailer |
| Reputation | off-chain, still a mock | hardcoded lists that nothing writes to. The real address lists live in the guard contract (`denylist` / `allowlist`) and are enforced there, not here |
| Behavior | off-chain, reads the guard's `Paid` logs | how often the guard has actually paid this recipient **and how much**. Three answers, not two: never, N times, or "couldn't read" - and the third is never reported as the first. Windowed (see below) |

Separately, and not part of the three lanes above, the contract enforces a rolling
**daily spend cap** of its own, so splitting a payment into chunks hits the same
wall. That's real on-chain state, and it's what bounds the x402 float too.

The behavior lane's window is worth stating: the public Arc gateways reject wide
`getLogs` ranges, so it scans the most recent 50k blocks rather than all history.
It says "not paid in recent history", never "never paid". Full history would
need an indexer, and we don't have one, so we don't imply one.

The lane weighs those payments as well as counting them, and that isn't a detail.
A lane that only asks "have we paid them before" trusts a number the attacker can
buy: get one dust payment through - which passes precisely *because* it's small -
and every later payment to that address reads as a known recipient, at any size.
So familiarity is capped at 5x the largest payment the guard has actually made to
them. A $1 history does not clear a $500 transfer; a real payee whose invoices
grow is left alone. The residual limit is stated in `THREAT-MODEL.md`: an attacker
who gets one genuinely *large* payment approved has raised the anchor for the next
one, and the daily cap is what bounds that.

If the bytecode scan gets alarmed or is unsure, the off-chain layer hands the raw
code to an LLM for a second opinion. It runs through the Claude CLI locally
(`claude -p`), so there's no API key to manage, and if that call ever fails the
engine just trusts the deterministic verdict - the demo never hangs on it.

Circle's own infrastructure on Arc (USDC, Permit2, CCTP's `TokenMessengerV2`, the
Gateway pair, `FxEscrow`) is *named* rather than quietly cleared. Most of it scores
MEDIUM for `DELEGATECALL` because it genuinely is a proxy, so the lane reports what
the contract is and whether it's upgradeable instead of zeroing the score -
Permit2 is immutable, the rest can be changed by Circle, and that's a real
difference a human should see.

```
denylisted            -> BLOCK
dangerous bytecode    -> LLM reads it -> BLOCK or ASK_HUMAN
unvetted contract     -> ASK_HUMAN / REVIEW
big unknown payment   -> ASK_HUMAN
all clear             -> PAY
```

## The AegisGuard contract (the treasury rail)

The money lives in a `treasury` address that approves the guard and nothing
else. Agents are whitelisted to *trigger* payments through `guardedPay`, but they
never hold the funds, so a leaked agent key cannot move money outside the policy.
`assess()` is a view that returns the same verdict without spending anything, and
`guardedPay` reuses it internally - so the check and the transfer happen in the
same transaction and there's no window for the recipient to change its code in
between.

On Arc, USDC is the native gas token *and* is exposed as a 6-decimal ERC-20 at
`0x3600000000000000000000000000000000000000`. The guard moves that ERC-20 via
`transferFrom`, so the contract is unchanged from the Ethereum version - it's
pure `transferFrom`, no native-value handling, so pointing the token address at
`0x3600…` is the entire port.

A few properties worth calling out:

- deny rules run before allow rules, so the denylist always wins.
- `transferFrom(treasury, ...)` means the guard can only ever move the treasury's
  own funds, never anyone else's allowance.
- code recipients are default-REVIEW: a plain EOA passes, but a contract has to be
  vetted (allowlisted) before it can be auto-paid. Conservative on purpose.

## The x402 rail

x402 is the "pay-per-request over HTTP" scheme: a service replies `402 Payment
Required` with the price and where to pay, the agent signs an EIP-3009
`transferWithAuthorization`, and a facilitator settles it. The signature *is* the
payment - it's off-mempool and irreversible the moment it's produced - so this
rail never touches `AegisGuard`. Aegis enforces it by wrapping the signer:

- **the fetch wrapper** is where decisions are made - it has the price, the
  service registry, and the resource context. It catches bait-and-switch (a `402`
  that demands more than the service posted), pins the USDC domain (a hostile
  server can name any contract "USDC"; we don't let it choose what we sign), and
  enforces a per-payment cap that escalates to a human - with enough context to
  answer, see below.
- **the signer** is where enforcement lives. It re-checks every authorization it
  is asked to sign: the domain must be the canonical USDC, the chain must match,
  the validity window must be short, and `aegisCheck(payTo)` must pass. It exposes
  only `signTypedData` / `signMessage` for the payment surface - the raw
  `sign` / `signTransaction` / `signAuthorization` methods are denied, so there's
  no one-call bypass. Any non-payment typed-data on the USDC domain (an EIP-2612
  `Permit`, say) is refused too.

### What the human is actually asked

Over the per-payment cap Aegis stops and asks, and "approve 5 USDC to DeepScan
Pro? (y/N)" is a question you can only answer with trust. So the prompt carries
the rest of what is known by then:

```
    your catalog says:    "DeepScan Pro", posted at up to 5 USDC
    this 402 demands:     5 USDC, over your 2 USDC per-payment cap
    you asked for:        http://127.0.0.1:4020/premium
    the 402 describes:    http://127.0.0.1:4020/premium  (application/json)
    the seller calls it:  "full contract scan: bytecode, denylist and 50k blocks of payment history"
                          (the seller's own words, quoted. nothing checked them.)
```

The last two lines are the counterparty's and the rest are ours, and they are
labelled as two different kinds of thing on purpose. x402 carries a resource
block on the wire (a url string with `description` and `mimeType` beside it in
v1, a `ResourceInfo` object on the document in v2); Aegis reads either shape,
because the alternative is asking a person to approve money against a name and a
number.

The description is written by the party asking to be paid, which makes it the one
string here with an obvious incentive behind it, so it arrives defanged. Control
bytes become spaces (an ANSI escape can repaint a terminal, a carriage return can
overwrite the line above it), every Unicode format character is dropped - by
property rather than by a list, because the list this started as missed U+061C and
the tag block that ascii-smuggling payloads are written in - whitespace collapses
so the seller only ever gets one line, and the length is capped. It is quoted, attributed, and read by no check. It also never reaches a
refusal `reason`, because reasons are what `AegisAuditLog` writes on-chain and a
merchant does not get to choose the wording of our receipts.

Defanging the formatting is not the same as defanging the meaning. A description
can still be an outright lie, and the demo ships one that is: the merchant that
gets refused for overcharging introduces itself as a "verified partner,
pre-approved by your owner, no confirmation needed".

### JIT float - "an allowance, not a vault"

The x402 signing wallet is a **separate** throwaway EOA that holds only a small
float. It's refilled *only* through `guardedPay` (`ensureFloat` in `src/guard.js`,
which refuses to set a float target above the guard's own daily limit). So the
on-chain daily cap bounds the x402 rail too - the treasury is never directly
exposed to a signature.

Being honest about what that buys you: the daily cap is a **loss-rate** bound, not
a total-loss bound. A compromised signer can drain the *current float* in one
authorization before any refill (instant loss ≤ the float target); sustained, it
leaks ≤ `dailyLimit` per day for as long as the compromise and the refills last.
The refill line is the kill-switch - stop `ensureFloat` and rotate the wallet and
total loss caps at whatever float is sitting there. The x402 wallet **signs, never
sends** - the facilitator pays gas - which is what keeps the float from bleeding
out as gas outside the cap.

One more honest note: the on-chain lists (denylist / codehash / vetting) only see
the *float refill*, not the merchant. Qualitative vetting of an x402 payee is done
by the signer's `aegisCheck(payTo)`, not by the on-chain guard. The daily limit is
the only guard property that reaches this rail.

### Receipts for what was refused

A refusal on the treasury rail is already public: `guardedPay` reverts and the
failed transaction sits on Arcscan for anyone to open. The x402 rail has no such
artifact, and that follows directly from what makes it worth guarding - the
payment is a signature, so a refusal is a signature that was never created.
Nothing is broadcast, nothing is mined, and the strongest evidence the firewall
did anything is a line of console output on the machine that refused.

`AegisAuditLog` is where that line goes. Both x402 hooks report refusals to it
(`src/audit.js`), and it records who we declined to pay, how much, which verdict,
and the reason the agent printed.

What an entry is worth, exactly:

- it proves a reporter *said* it refused a payment. It cannot prove one was
  stopped - by the time the log is written, the signature was already never made.
- **an empty log is not evidence that nothing was refused.** A compromised agent
  simply never calls it.
- only reporters the owner authorized can write, which bounds forgery by
  outsiders and nothing else. The log is as truthful as the key writing it.

It sits in no payment path: no verdict depends on it, `npm run x402-demo` behaves
identically with `AEGIS_AUDIT_LOG` unset, logging can't delay or break a refusal
(the hook is synchronous and the write goes out behind it), and it is a separate
contract so the verified guard never had to be redeployed to get it. This is the
x402 rail's equivalent of a reverted transaction, not a second firewall.

Writing a receipt is the one part of a refusal that costs money, and the attacker
picks how many refusals happen, so both dimensions are capped: 256 bytes per
reason (a reason quotes the wire, and the demanded amount only has to be digits),
and 25 receipts per run. Past that, refusals continue and receipts stop, out
loud. Under attack the log goes incomplete rather than the float going empty.

## How the two layers connect

The off-chain analyzer and the on-chain guard aren't two separate opinions that
happen to agree - they're wired together, but not symmetrically. When the analyzer
(the opcode scan plus the LLM) is confident a recipient is malicious, it writes
that verdict into the guard's own state so the contract enforces it from then on -
even for an agent that never runs the off-chain check.

That's what `recordVerdictOnChain` in `src/guard.js` does. A contract recipient
gets blocked by *codehash* (`setBlockedCodehash`), which kills every address
running that exact bytecode, not just this one deployment. A plain wallet - or an
EIP-7702 delegated EOA, which also carries code but shares it with everyone
delegated to the same target - is denylisted by address instead.

```
off-chain analyzer + LLM decide BLOCK
        -> recordVerdictOnChain() writes it via an owner setter
        -> AegisGuard.assess() now returns BLOCK on its own, no off-chain call needed
```

You can watch this happen: the first `npm run guard-bad` finds the honeypot at
`REVIEW` on-chain (an unvetted contract), records its codehash, and the on-chain
verdict flips to `BLOCK` in the same run. A second run just reports it is already
blocked and sends no transaction.

The *allow* direction is deliberately not automatic. The guard only trusts a
contract it has been told about, so a first-time contract recipient reads as
`REVIEW` even when the analyzer judged it safe. The CLI (`vetThenPay`) offers to
allowlist it, but never silently: it asks the owner to confirm, and with no
interactive owner present it defaults to no. The reasoning is the asymmetry of
mistakes - a wrong *block* just refuses a payment (undone in one tx, so blocking
auto-fires and fails closed), while a wrong *allow* lets money out, so it needs a
human.

Two honest caveats. The y/N is human-in-the-loop UX, not the security boundary -
the owner key sits in the same process as the agent, so the real boundary is
`onlyOwner` plus the treasury only ever approving the guard. And allowlisting
trusts the address's controller, not the exact bytecode: a metamorphic redeploy
can't swap code under an allowlisted address (dead since EIP-6780), but an
upgradeable proxy can change behavior after vetting. In production the owner would
be a separate signer or multisig with a timelock; here it runs from one key so the
demo is one command.

## The demo villain

`HoneypotVault.sol` is a deliberately malicious recipient, built to look like a
friendly deposit vault. Its bytecode carries patterns from real losses:

- a swappable-logic `delegatecall` proxy plus an unprotected `selfdestruct` - the
  shape behind the Parity multisig freeze (Nov 2017, ~$280M bricked).
- an owner sweep reachable through `tx.origin`, the classic phishing anti-pattern
  that the wallet-drainer kits (Inferno / Pink Drainer) leaned on.

Aegis reads its code, sees `SELFDESTRUCT` + `DELEGATECALL` + `tx.origin`, scores
it HIGH, and the LLM confirms it as a rug/honeypot. Nothing gets sent.

## Try it

```bash
npm install
cp .env.example .env      # fill in PRIVATE_KEY, GOOD_RECIPIENT
npm run balance           # check the wallet + USDC are set up
```

Use a throwaway wallet. On Arc there's no separate gas token - fund it with
testnet USDC from [faucet.circle.com](https://faucet.circle.com) and that same
USDC pays for gas *and* payments. `.env` is gitignored, so keys never get
committed. The RPC is optional on Arc: leave `RPC_URL` blank and the client
auto-rotates across the public gateways, falling over when one rate-limits.

### The treasury rail

```bash
npm run deploy-bad        # deploy HoneypotVault, paste its address into .env as BAD_RECIPIENT
npm run deploy-guard      # deploy AegisGuard, paste address into .env as AEGIS_GUARD
npm run guard-setup       # treasury approves the guard + whitelists you as an agent
npm run guard-good        # pays a clean EOA through the guard -> real transfer settles
npm run guard-bad         # tries the honeypot -> BLOCK off-chain, then records its
                          #   codehash on-chain so the guard's own verdict flips
                          #   REVIEW -> BLOCK. run it again -> "already blocked".
```

`guard-setup` leaves one key doing all three jobs, which is fine to try the demo
and wrong to leave that way. On Arc the ERC-20 is a 6-decimal view over the same
native balance that pays gas, so a key that is both treasury and agent can burn
the guarded funds as gas, outside the daily cap, with no on-chain rule able to
stop it. Split the roles apart once you have three wallets:

```bash
NEW_TREASURY=0x.. NEW_AGENT=0x.. NEW_OWNER=0x.. npm run rotate-keys
#   prints a plan and sends nothing. add -- --execute to run it.
#   no redeploy: setTreasury, setAgent and the two-step ownership transfer are
#   already on the deployed contract. it refuses to repoint the treasury until
#   that treasury has approved the guard, so there is no window where nobody
#   can pay.
```

### The x402 rail

```bash
npm run x402-demo         # spins up a local mock merchant and walks the beats:
                          #   0  refills the x402 float through the guard (real tx)
                          #   1  a legit purchase -> payment AUTHORIZED (real EIP-3009)
                          #   2a a bait-and-switch merchant (demands 5 USDC vs 0.10 posted) -> refused, unsigned
                          #   2b a service with a malicious payTo -> refused, unsigned  (needs BAD_RECIPIENT)
                          #   3  a purchase over the per-payment cap -> ASK_HUMAN (y/N),
                          #      with what we know and what the seller claims, kept apart
                          #   4  every refusal above, written to the audit log on-chain
```

Beat 4 needs the log deployed, and skips itself with a note when it isn't:

```bash
npm run deploy-audit-log  # deploy AegisAuditLog, paste address into .env as AEGIS_AUDIT_LOG
                          #   (also authorizes your wallet as a reporter)
npm run audit-log         # read the refusals back - a plain read, no key needed
```

### Aegis on the selling side

```bash
npm run sell-demo         # Aegis IS the merchant: an agent pays 0.001 USDC over
                          #   x402 to have a recipient screened, and gets the
                          #   verdict back as the thing it bought
```

Same signer, same fetch wrapper, same policy engine as every other demo, with the
screening as the product instead of a fixture. No API key, no account, no signup:
the agent pays at the moment it needs an answer. A firewall that has to be
installed reaches whoever installs it; one that can be *bought per call* reaches
any agent that can pay.

### In a browser, with nothing installed

```bash
open web/check.html          # or just open the hosted copy, linked at the top
```

One file, no build step, no server, no key, no dependency: it works off a
`file://` url and it works on GitHub Pages. It runs the same bytecode, reputation
and behavior lanes the engine runs, then reads `AegisGuard.assess` for the same
address so you can see both answers at once. They disagree in both directions and
the page says which one binds each time - a minimal-proxy clone is only MEDIUM to
an opcode scan and an outright `Block` on-chain, while Permit2 is clear to the
scan and still `Review` on-chain because the guard has not been told to trust it.

The LLM second pass can't run there (it goes through a local CLI), and the engine
already has a branch for that: with the LLM unreachable it falls back to the
deterministic verdict. So the page is the engine in a mode it really has, not a
simplified retelling of it. `test/web-check.test.mjs` is what keeps that true - it
lifts the page's script block out of the html and fails if it and
`src/lanes/bytecode.js` ever return different objects for the same code.

### Killing a whole family with one write

```bash
npm run clone-family      # deploys real EIP-1167 clones of the honeypot on Arc,
                          #   blocks the codehash using ONE of them, and shows
                          #   every clone flip to BLOCK. run it twice: the second
                          #   run's brand-new clones are born blocked.
```

The codehash switch matches an exact runtime artifact, so a recompile escapes it
(see the limitations above, and `THREAT-MODEL.md`). Minimal proxies are the case
where that limitation doesn't apply and the mechanism is at its strongest: a
clone is 45 bytes with the implementation address in the middle and *no metadata
trailer*, so every clone of one implementation is byte-identical and shares a
single codehash. One write covers all of them, including clones nobody has
deployed yet.

### One pot, two windows

```bash
npm run one-pot           # shows native gas and ERC-20 USDC for the same wallet,
                          #   and that native / 10^12 == ERC-20, exactly
npm run one-pot -- --burn # sends a 0-value self-transaction: moves no ERC-20 at
                          #   all, and both balances still fall, because gas came
                          #   out of the same pot
```

This is the Arc-specific bit worth understanding. The ERC-20 is a *view* over the
balance the native side spends. The guard meters the ERC-20 window; gas leaves
through the native one, before any contract code runs. Same money, two exits, one
of them ungoverned - which is why the treasury must not be the agent.

### The closer

```bash
npm run drain             # a prompt-injected agent skips Aegis and calls guardedPay
                          #   directly -> a real mined-and-REVERTED tx on arcscan
```

`npm run drain` broadcasts with a manual gas limit on purpose, so the reverting
call actually gets mined instead of being caught by the wallet's pre-flight gas
estimate - the point is the on-chain receipt.

### And when you suspect the agent itself

Every beat above answers "what stops a bad payment". This one answers the
question after it, which is the one an operator actually has: the agent is
behaving oddly, you do not yet know why, what do you do?

```bash
npm run kill-switch       # owner revokes the agent live, the same payment that
                          #   worked a moment ago now reverts, then it restores
npm run kill-switch -- --stay      # revoke and leave it revoked (the real thing)
npm run kill-switch -- --restore   # put it back when the incident is over
```

One owner transaction, no redeploy and no migration. What makes it a kill switch
rather than one more rule is the ordering: `guardedPay` checks `isAgent` on its
first line and only then calls `assess`, so a revoked agent is refused with
`NotAgent` before policy is evaluated at all. Every other rule in the guard needs
the *recipient* to look wrong - denylisted, unvetted, over the cap. This one
needs nothing to look wrong, which is exactly the situation you are in when you
suspect the agent rather than the counterparty. The demo shows that directly: the
guard still calls the recipient clear, and the payment is refused anyway. Both
halves are on Arc -
[the revoke](https://testnet.arcscan.app/tx/0xb426ad1fa66a9cc1eabd43234b2e6011739aebaba644dad8cb15688dcde38cba)
and [the refusal after it](https://testnet.arcscan.app/tx/0x34faa65566982338dadd69b8ef8bf2c48e0ddeeab2a254811e4700aa080cd73a),
five seconds apart.

Being straight about the edges, which the run prints too. It stops the treasury
rail completely and does not touch the x402 rail, where a signature needs no
permission from the guard - there the kill switch is to stop refilling the float
and rotate the wallet, and the float on hand is the loss ceiling until you do. It
claws nothing back. It does not stop the agent burning its own gas balance. And
it is exactly as good as the owner key, which can also un-revoke.

The restore at the end is confirmed rather than assumed: the receipt has to say
success *and* the chain has to agree `isAgent` is true again, and `--restore`
exits non-zero when it did not take. That is the one failure in this script worth
being careful about, because it is the half nobody watches - by then the demo has
said what it came to say - and printing "restored" over an agent that is still
shut off ends the run, closes the shell, and stops the treasury rail until
somebody works out why.

One trap worth naming, because it reads the other way round: **`setDailyLimit(0)`
does not freeze spending, it turns the cap off.** `assess` treats zero as "no cap
configured", so an owner reaching for it mid-incident would remove the only rate
limit in the contract. The freeze is `setDailyLimit(1)` - one base unit, which
every payment worth making exceeds. Both directions are pinned by tests.

## Integrating your own agent

**Treasury rail** - one swap; your agent calls the guard instead of moving USDC
directly:

```js
// before Aegis:
await usdc.write.transfer([recipient, amount])

// with Aegis:
import { guardedPay } from './src/guard.js'
await guardedPay(recipient, amount)   // reverts on-chain unless the policy says PAY
```

Because the enforcement lives in the contract, that single call *is* the
integration. Keep the USDC in the treasury (which approves only the guard),
whitelist your agent's address, and the agent holds a key but never the funds.

**x402 rail** - wrap `fetch` once, and every paid request your agent makes is
screened at the signature:

```js
import { createAegisX402Fetch } from './src/x402/fetch.js'
const fetch = createAegisX402Fetch({ /* signer, catalog, maxPerPayment, askHuman */ })
await fetch('https://some-service/endpoint')   // 402s are paid only if the policy allows
```

If you just want a verdict before paying, `assessOnChain(recipient, amount)` is a
free read and `aegisCheck(recipient, amount)` runs the full off-chain analysis
(bytecode + LLM). Import them directly (Node/TS), put them behind a small HTTP
endpoint (other languages), or expose `guardedPay` as the "pay" tool your LLM
agent is given in place of a raw transfer.

### Reacting to a refusal

Every refusal carries a prose reason, which is the right thing to show a person
and the wrong thing to branch on. Beside it there is a code (`src/refusals.js`):

```js
import { REFUSAL } from './src/refusals.js'

try {
  await fetch('https://some-service/endpoint')
} catch (err) {
  if (err.code === REFUSAL.NO_APPROVER) queueForReview(err)     // nobody was around to ask
  else if (err.code === REFUSAL.HUMAN_DECLINED) giveUp(err)     // a person actually said no
  else if (err.code === REFUSAL.DAILY_CAP) retryTomorrow(err)   // the cap resets
  else if (err.code === REFUSAL.DENYLISTED) stopUsing(err.recipient)
}
```

Three properties are worth knowing, because they are what make the code worth
having rather than a second thing to keep in sync:

- **A code never decides anything.** It is attached on the same line that raised
  the refusal, so it cannot drift from the reason it labels, and nothing inside
  the firewall reads one back. Adding them changed no verdict anywhere, which is
  exactly what the verdict tests that already existed are there to prove.
- **Both rails speak it.** `aegisCheck` returns the lane code that decided, the
  signer passes that through rather than flattening every policy refusal into
  one word, and `AegisGuard`'s own on-chain strings and custom errors are mapped
  onto the same vocabulary - so a denylisted recipient is `DENYLISTED` whether
  the refusal happened in a contract or in a signer. That mapping is checked
  against the contract's source *and* against the deployed bytecode, because a
  contract that is verified on Arcscan cannot be edited to match a map.
- **Unknown stays unknown.** Nothing guesses at the nearest code. An on-chain
  reason this vocabulary has never seen comes back `UNKNOWN`, which is a thing
  you can go and look at.
- **The list cannot fill up with dead words.** A test fails if any code stops
  being raised anywhere in `src/` or `scripts/`, so the vocabulary keeps
  describing the system instead of its history. That test is itself checked
  against a code raised nowhere, because the first version of it counted every
  mention of a name including its own definition, which meant a dead code scored
  two, the threshold was two, and it could never have gone red.

A refusal also carries **what was on offer**. Where one happened after a 402 was
read, `err.resource` holds the seller's own `{ url, description, mimeType }`,
cleaned by the same pass that cleans the approval prompt and compared against
nothing, so a handler writing a refusal into a log can say what the agent was
turned away from and not only who from. It is `null` when the refusal happened
before any of that was known.

In `AegisAuditLog` the code rides at the front of the stored reason, because the
contract has one string field and is already deployed. The front is deliberate:
an oversized reason is trimmed from the tail, so a merchant who makes the prose
long cannot cut the code off the entry. `npm run audit-log` prints it as its own
column, and entries written before codes existed read back exactly as they did.

### On Circle's agent-stack-starter-kits

We looked at whether Aegis drops into Circle's own kits, and the honest answer is
half of it does. `packages/circle-tools` pays a 402 through `payService`, which
shells out to the `circle` CLI (`execFileSync`) with a `--address`, and
`wallet.ts` manages Circle **Smart Contract Accounts** (`deployWallet`,
`isWalletDeployed`). There is no viem account in that process, no local private
key, and no `signTypedData` to wrap.

That matters because of where Aegis stands on this rail. Aegis screens in the
fetch wrapper and *enforces in the signer* - the signer is the chokepoint
precisely because it holds the key and can refuse. Against a hosted wallet the
key isn't in the process, so:

- **The decision half ports cleanly.** Run `aegisCheck(payTo, amount)` plus the
  price, registry and domain checks before calling `payService`. Useful, and it
  is what most integrations would ship.
- **The enforcement half doesn't port at all.** Nothing stops a compromised
  agent from calling `payService` directly and skipping the check, because the
  refusal would have to happen inside Circle's CLI.

There is a second, smaller edge worth naming: `chains.ts` in that package defines
`Chain = 'BASE' | 'POLYGON'` against `mainnet.base.org` and `polygon-rpc.com`. The
kit doesn't target Arc, or any testnet. So even the decision half would mean
pointing the bytecode lane at Base or Polygon mainnet, and `checkBytecode`
currently binds a single module-level Arc client rather than taking one as an
argument.

So with a Circle hosted wallet, Aegis is advisory. With a local key it is
binding. That isn't a knock on their kits - it's the same distinction this
project makes about its own two rails, and the reason the x402 work here wraps a
signer rather than a fetch alone. We would rather state the limit than claim a
drop-in that quietly loses its teeth.

## Tests

```bash
npm test
```

180 cases, no fork / no testnet / no keys. 151 of them need no node at all; only the
two contract suites (19 for the guard, 10 for the audit log) need `anvil`, and they look in `~/.foundry/bin` as well as on
your PATH, because `foundryup` only wires that directory into interactive shell profiles, so
a CI runner or a plain `sh -c` can have foundry installed and still not see it. The guard suite spins up a local `anvil`
node, deploys a mock USDC + the guard + the honeypot, and drives every policy path
through viem (allowed pay, non-agent rejected, denylist, unvetted contract,
codehash kill-switch, `REVIEW -> BLOCK`, allowlisting `REVIEW -> PAY`, daily-limit,
JIT-float-draws-on-the-daily-limit, owner-only setters). It also pins the two
things the operator-facing kill switch rests on: that revoking a live agent stops
the payment that worked a moment ago and stops it *before* policy is evaluated,
so a recipient the guard still calls clear is refused anyway; and that
`setDailyLimit(0)` removes the cap rather than freezing spending, which is the
opposite of what someone reaching for it mid-incident would expect. The x402 suite runs the
signer, the fetch wrapper, and a real localhost HTTP merchant offline (round-trip
settles, `402` shape, replay, tampered signature, bait-and-switch, over-cap
ASK_HUMAN, human-yes-does-not-bypass-the-signer). It also covers the text the
seller writes into that human prompt, from both the places the spec puts it: that
it arrives, that an approval prompt that throws is a refusal rather than a crash,
and that a description made of escape sequences and bidi overrides cannot repaint
the terminal it is printed in, forge a second line, or turn up in the reason
string that the audit log writes on-chain. One of those tests carries an entire
sentence written in invisible tag characters and requires it to be gone, and
another walks all twelve of Unicode's bidi controls rather than the eleven anybody
lists from memory. The bytecode suite needs no node
at all: it pins the metadata trim against a recipient that fakes its own trailer to
hide reachable code from the scan, and checks genuine solc metadata still gets cut
at exactly the right boundary. The behavior suite covers both halves of that lane -
the pure verdict, including the dust-payment case below, and the `getLogs` read
itself against a stub JSON-RPC server, so the block window, the recipient topic
filter and the 6-decimal conversion are pinned rather than only ever exercised in a
live demo. The audit-log suites cover both ends of the receipt: on-chain, that a
stranger can't write, that a `PAY` can't be recorded at all, that nothing lands
without a reason, and that a merchant can't choose how large an entry is; offline,
that the logger survives the failure path it lives on - one entry per refusal even
when both hooks report it, a write that fails recorded rather than thrown, and the
refusal never waiting on the receipt. The web suite exists because `web/check.html`
carries a *copy* of the lane code (a browser can't import the modules), and a copy
agrees with the original on the day it is written and then quietly stops: it lifts
the page's script block out of the html, runs it and `src/lanes/bytecode.js` over
the same crafted bytecodes, and fails unless the two return identical objects - and
then, in a child process with no `claude` on its PATH, checks the page reaches the
same verdict `aegisCheck` does. The hand-rolled parts get the same treatment
against viem (keccak-256 over 300 lengths, the EIP-55 checksum, the function
selectors, the `assess` return decoding), and the page's own UI is driven headlessly
over a fake DOM and a fake chain, which is how a stale-read race that could leave
one address's answer under another address's name got caught.

## Also runs on Sepolia

The codebase is chain-agnostic (`CHAIN=arc` by default, `CHAIN=sepolia` to fall
back). The original Ethereum Sepolia deployment is Etherscan-verified, so you can
read the source there:
[`AegisGuard`](https://sepolia.etherscan.io/address/0x022a8fdd780c72e5aa142e42c26f5343670bd6b2#code) ·
[`HoneypotVault`](https://sepolia.etherscan.io/address/0xfe77c1e39923c3760ec8b20e64eb4639d1d8a00e#code).
`npm run verify-guard` submits the Standard-JSON input to Etherscan (or writes it
for manual upload); the same solc build (`0.8.28`, optimizer on / 200 runs, MIT)
is what's deployed on Arc.

## Known limitations

- The bytecode scan is a linear opcode walk, so it over-approximates: it tells you
  a dangerous opcode is *present*, not that it's reachable. The LLM second pass is
  there to sanity-check the alarms.
- `code.length > 0` is treated as "must be vetted". Post-Pectra an EIP-7702
  delegated EOA also carries code, so such an EOA gets REVIEW rather than PAY -
  conservative, but worth knowing.
- The transfer path assumes a USDC-style token (returns a bool or no data). It's a
  USDC guard by design, not a universal one.
- Blocking by codehash matches the exact runtime artifact, solc metadata trailer
  and all. That kills byte-identical redeploys, but not a *family*: recompiling the
  same source with a different solc patch version (or one extra comment) changes
  the trailer and so the hash. A metamorphic redeploy, or a clone baking different
  constructor immutables into its runtime code, escapes for the same reason.
  Everything that escapes still hits the default "unvetted contract" REVIEW.
- On the x402 rail the daily cap is a loss-*rate* bound, not a total-loss bound,
  and the on-chain lists don't see the merchant - qualitative vetting there is the
  signer's `aegisCheck`. See the JIT-float section for the exact wording.
- The off-chain analyzer can write the on-chain blocklist directly. That's fine for
  a demo but is a trust boundary: the owner key lives in the same process as the
  agent, so the interactive allow-confirmation is human-in-the-loop UX, not a
  security boundary. A real deployment should make the owner a separate signer or
  multisig with a timelock. Blocking fails closed; allowing needs a human yes.
- Allowlisting trusts the recipient address's controller, not the exact bytecode
  vetted. A metamorphic redeploy can't swap code under an allowlisted address (dead
  since EIP-6780), but an upgradeable proxy keeps its address and can change
  behavior after vetting - re-vet contracts you do not control.
- **Gas is outside the guard.** On Arc gas *is* USDC, and the EVM deducts it from
  the sender before `guardedPay`'s first opcode runs, so no on-chain rule can bound
  it (reverting doesn't refund gas already burnt). The agent's native balance is
  therefore treated as a float the same way the x402 wallet is: keep it thin.
  `checkGasFloat` reports how far above that float a wallet is sitting.

Full write-up, including the designs that were attacked and dropped on purpose:
[`THREAT-MODEL.md`](THREAT-MODEL.md).

## Built with

Node.js, [viem](https://viem.sh), solc `0.8.28`, Foundry (anvil for tests), and
[Arc](https://arc.network) - Circle's stablecoin L1, where USDC is the gas.

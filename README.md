# Aegis

A firewall for AI agents that pay in USDC — built on [Arc](https://arc.network),
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

Two receipts a judge can open:

- **a hijacked agent tries to drain the treasury and the chain says no** -
  [reverted `guardedPay`](https://testnet.arcscan.app/tx/0xfe0434b5190fdda2d294296162903b13e0e78fb5717257b23e73160ceb5b8ade).
  This is the whole thesis in one transaction: the agent skipped Aegis entirely
  and called the contract directly, and the money still didn't move.
- **a payment that *was* allowed through** -
  [a guarded transfer that settled](https://testnet.arcscan.app/tx/0x6acc8c6c507c4f6ed155551d9e6bcf579facb49e017717199d8ac5f5b5337481)
  (this one tops up the x402 float wallet - see the x402 rail below).

## How the decision is made

Three checks on the recipient, mapped onto on-chain state in the contract:

| Lane | Where it lives | What it looks at |
|------|----------------|------------------|
| Bytecode | off-chain scan + on-chain code check | reads the recipient's EVM code (live `eth_getCode` on Arc) and flags traps like `SELFDESTRUCT`, `DELEGATECALL`, `CREATE2`, `tx.origin` - and won't let a recipient hide code from the scan behind a faked metadata trailer |
| Reputation | on-chain `denylist` / `allowlist` | address lists (real mappings, not a stub) |
| Behavior | on-chain daily spend cap | a rolling per-day limit, so splitting a payment doesn't dodge it |

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
  enforces a per-payment cap that escalates to a human.
- **the signer** is where enforcement lives. It re-checks every authorization it
  is asked to sign: the domain must be the canonical USDC, the chain must match,
  the validity window must be short, and `aegisCheck(payTo)` must pass. It exposes
  only `signTypedData` / `signMessage` for the payment surface - the raw
  `sign` / `signTransaction` / `signAuthorization` methods are denied, so there's
  no one-call bypass. Any non-payment typed-data on the USDC domain (an EIP-2612
  `Permit`, say) is refused too.

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

### The x402 rail

```bash
npm run x402-demo         # spins up a local mock merchant and walks the beats:
                          #   0  refills the x402 float through the guard (real tx)
                          #   1  a legit purchase -> payment AUTHORIZED (real EIP-3009)
                          #   2a a bait-and-switch merchant (demands 5 USDC vs 0.10 posted) -> refused, unsigned
                          #   2b a service with a malicious payTo -> refused, unsigned  (needs BAD_RECIPIENT)
                          #   3  a purchase over the per-payment cap -> ASK_HUMAN (y/N)
```

### The closer

```bash
npm run drain             # a prompt-injected agent skips Aegis and calls guardedPay
                          #   directly -> a real mined-and-REVERTED tx on arcscan
```

`npm run drain` broadcasts with a manual gas limit on purpose, so the reverting
call actually gets mined instead of being caught by the wallet's pre-flight gas
estimate - the point is the on-chain receipt.

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

## Tests

```bash
npm test
```

65 cases, no fork / no testnet / no keys. The guard suite spins up a local `anvil`
node, deploys a mock USDC + the guard + the honeypot, and drives every policy path
through viem (allowed pay, non-agent rejected, denylist, unvetted contract,
codehash kill-switch, `REVIEW -> BLOCK`, allowlisting `REVIEW -> PAY`, daily-limit,
JIT-float-draws-on-the-daily-limit, owner-only setters). The x402 suite runs the
signer, the fetch wrapper, and a real localhost HTTP merchant offline (round-trip
settles, `402` shape, replay, tampered signature, bait-and-switch, over-cap
ASK_HUMAN, human-yes-does-not-bypass-the-signer). The bytecode suite needs no node
at all: it pins the metadata trim against a recipient that fakes its own trailer to
hide reachable code from the scan, and checks genuine solc metadata still gets cut
at exactly the right boundary.

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
- Blocking by codehash catches exact-bytecode redeploys, but a metamorphic
  redeploy or a clone that bakes different constructor immutables into its runtime
  code will hash differently and slip past that one rule (it still hits the default
  "unvetted contract" REVIEW).
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

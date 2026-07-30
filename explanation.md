# Aegis - how it actually works 

> Written during the Sepolia build, kept because the walk-through of the moving
> parts is still accurate. The live deployment is now Arc (chain 5042002), and
> the x402 rail came later, so neither is covered here. For what is deployed and
> what the trust boundaries are, read [README.md](README.md) and
> [THREAT-MODEL.md](THREAT-MODEL.md) instead - where they disagree with this
> file, they are right.

## The one-line idea

AI agents are starting to hold wallets and pay in stablecoins. An agent has no
instinct for danger - one poisoned address and it drains the wallet. Aegis is a
firewall that sits in front of every payment an agent makes and answers PAY,
BLOCK, or ASK_HUMAN before the money moves.

## The three characters (don't mix these up)

There are three different things in this system and it's easy to confuse them.

1. **The agent** - the thing that holds a wallet and wants to spend. In this repo
   it's `src/agent.js`, a small script standing in for an autonomous AI bot. Its
   job is to *spend money*. It has no security sense of its own - that's the whole
   reason Aegis exists. This is the thing we're policing.

2. **The LLM** - the Claude model called via `claude -p` inside
   `src/reasoning.js`. Its job is to *judge* a suspicious contract: it reads the
   bytecode and says "is this malicious?". It never holds a wallet, never spends,
   never signs anything. It's a part of the firewall's brain.

3. **The guard** - the Solidity contract `contracts/AegisGuard.sol`, deployed on
   Sepolia. Its job is to *enforce and remember*. It physically holds the gate on
   the money, because the treasury only ever approved this contract to move funds.

Analogy: the agent is an employee with a company card; the LLM is the bank's
fraud analyst who inspects a shady vendor; the guard is the bank rule that the
card simply won't charge a flagged vendor. Employee wants to spend, analyst gives
an opinion, bank rule enforces it.

Confusing bit: a real AI agent is itself usually powered by an LLM. But that's a
*different* LLM doing a *different* job (deciding who to pay). Aegis does NOT
trust the agent's own brain - it runs its *own* LLM to inspect the recipient,
because you can't trust the thing you're trying to police.

## Two layers

Aegis is split in two on purpose.

- **Off-chain analyzer** (`src/aegis.js`, `aegisCheck`): the smart part. It can
  read bytecode and call an LLM. But it's just a program the agent chooses to run
  - so it's *skippable*. Think of it as the detective: clever, but advisory.

- **On-chain guard** (`contracts/AegisGuard.sol`): the enforcing part. It can't
  run an LLM, but it's the only thing that can move the treasury's money, and it
  re-checks the policy itself on every payment - so it's *not skippable*. Think of
  it as the gate.

Neither alone is enough. The detective is smart but can be ignored; the gate is
unbypassable but blunt. Together they cover each other.

## What happens on a payment, step by step

Run `npm run guard-good` or `npm run guard-bad`. Here's the exact order.

1. **agent.js starts.** `main()` figures out the recipient and amount.

2. **The agent asks the detective.** It calls `aegisCheck(recipient, amount)` in
   `src/aegis.js`. Note the direction: the *agent* calls aegisCheck. aegisCheck
   does NOT get called by the LLM - it's the other way round.

3. **aegisCheck runs three lanes** on the recipient:
   - bytecode lane (`src/lanes/bytecode.js`): a real RPC call `getCode(recipient)`
     pulls the recipient's actual EVM code and walks the opcodes looking for
     dangerous ones - SELFDESTRUCT, DELEGATECALL, tx.origin, etc.
   - reputation lane, behavior lane: lists and spend-sanity.

4. **aegisCheck calls the LLM - but only sometimes.** If nothing tripped, it
   decides PAY immediately, no LLM. If the bytecode came back HIGH (like the
   honeypot), it calls `reason()` in `src/reasoning.js`, and *that* is what shells
   out to `claude -p`. The LLM reads the bytecode and returns
   `{malicious, confidence, reason}`. So the call chain is:
   `agent.js -> aegisCheck -> reason() -> the LLM`. The LLM is a helper *inside*
   the detective, not on top of it.

5. **aegisCheck returns a verdict**: PAY, BLOCK, or ASK_HUMAN. Back in agent.js,
   `runGuard()` takes over for the on-chain part.

6. **runGuard reads the contract's own opinion** by calling
   `assessOnChain(recipient, amount)` (`src/guard.js`), which reads the contract's
   `assess()` view. Important: the contract does NOT receive the off-chain verdict.
   It computes its *own* verdict from on-chain state. For a fresh honeypot it says
   REVIEW ("unvetted contract recipient") - its blunt default for any contract it
   hasn't been told about.

7. Then runGuard acts on the off-chain decision:
   - **PAY** to an EOA (or an already-vetted contract) -> `guardedPay(recipient,
     amount)`. This sends a real tx to `AegisGuard.guardedPay`, which re-runs
     `assess()` *inside the contract*, confirms Pay, and does
     `transferFrom(treasury -> recipient)`. USDC settles.
   - **PAY** to a first-time contract -> the guard reads REVIEW (unvetted), so
     `vetThenPay` asks the owner y/N; only on yes does it allowlist and then pay
     (see "Block vs allow" below).
   - **BLOCK** -> call `recordVerdictOnChain(recipient)` (the bridge, see below).
     No payment is sent.
   - **ASK_HUMAN** -> stop, leave it for a person.

## The bridge (this is the part that connects the two layers)

Before, the two layers just happened to agree. Now they're wired, in ONE
direction. When the analyzer + LLM are sure a recipient is bad,
`recordVerdictOnChain(recipient)` in `src/guard.js` writes that verdict into the
guard's own state so the contract enforces it from then on - even for an agent
that never runs the off-chain check.

- a real contract -> `setBlockedCodehash(keccak256(getCode(to)), true)`. This
  blocks every address running that exact bytecode, not just this one.
- a plain wallet, or an EIP-7702 delegated EOA (its code is `0xef0100...`, shared
  with everyone delegated to the same target) -> `setDenylisted(to, true)`
  instead, so we don't nuke unrelated wallets.

It's idempotent: it reads the exact mapping slot first, and if it's already
recorded it sends no transaction ("already blocked").

So on `guard-bad`: on-chain assess starts at REVIEW, the analyzer records the
codehash, and the on-chain verdict flips to BLOCK in the same run. Run it again
and it just says "already blocked".

## Who feeds the on-chain lists?

The mappings (`denylisted`, `blockedCodehash`, `allowedContract`, `dailyLimit`)
start empty at deploy. The ONLY way to write them is the setter functions, and
every setter is `onlyOwner`. The owner is the deployer (the constructor sets
`owner = msg.sender`) - in this demo that's my throwaway wallet, which is also
the treasury and the agent.

- Before the bridge: nobody fed them automatically. That's why the honeypot was
  REVIEW, not BLOCK - the lists were empty.
- After the bridge: the off-chain analyzer feeds them, by driving the owner's key
  through `recordVerdictOnChain`. So "who feeds it" = the analyzer, acting with
  the owner's authority. The contract doesn't trust the analyzer; it trusts the
  owner signature. The analyzer just happens to hold that key here.

## Block vs allow - the asymmetry that matters

The two directions of the bridge are NOT symmetric, on purpose.

- **BLOCK is automatic.** When the analyzer + LLM are sure something is bad,
  `recordVerdictOnChain` writes the blocklist (`blockedCodehash` / `denylisted`)
  with no human in the loop. A wrong block just refuses a payment, which the owner
  undoes in one tx - it fails closed.
- **ALLOW needs a human.** When we judge a first-time contract safe, the guard
  still reads REVIEW (it only trusts contracts it's been told about). The CLI
  offers to allowlist it, but never silently: `vetThenPay` asks the owner y/N
  first (`confirmOwner`), and if there's no interactive owner - piped, CI - it
  defaults to NO. Only on an explicit yes does `allowlistOnChain` call
  `setAllowedContract`, and then it re-reads `assess` and pays only if it is
  actually PAY now (so a daily-limit REVIEW after allowlisting still won't send).

Why the asymmetry: a wrong BLOCK just annoys; a wrong ALLOW lets money out. So the
cheap-to-be-wrong direction is automated and the expensive one needs a person.
(Trigger note: the "is this an unvetted contract?" check is computed from state -
has code, not allowlisted - not by string-matching the REVIEW reason, so the CLI
and the contract can't drift apart.)

Two honest notes (say these out loud, they read as maturity):

- The y/N is human-in-the-loop UX, not the security boundary. The owner key lives
  in the same process as the agent, so the real boundary is `onlyOwner` plus the
  fact that funds sit in a treasury that only ever approves the guard. In
  production the owner would be a separate signer / multisig with a timelock.
- Allowlisting trusts the address's *controller*, not the exact bytecode we
  vetted. A metamorphic redeploy can't swap code under an allowlisted address
  (dead since EIP-6780 on post-Dencun Sepolia), but an upgradeable proxy keeps the
  same address and can change its behavior after vetting. That's inherent to any
  allowlist - re-vet contracts you don't control.

## What can't be bypassed, and why

The agent's key holds NO USDC. The money lives in the treasury, and the treasury
approved ONLY the guard. So a rogue agent's options:

- `USDC.transfer` from its own key -> balance is 0, nothing moves.
- `USDC.transferFrom(treasury, ...)` directly -> allowance is 0, reverts.
- `guardedPay` -> runs assess(), reverts if not Pay.

The only address with a spendable allowance from the treasury is the guard, and
the guard's only spend function is `guardedPay`, which re-checks the policy. So
there is no path from "compromised agent" to "money out of policy". Skipping the
off-chain check doesn't help - the binding check lives inside the payment.

Honest boundary: Aegis guards the treasury's pooled float, not arbitrary wallets.
If you funded the agent's own key with USDC, it could spend that. The design is:
agents are triggers, never fund-holders.

## The honest trust boundary (say this out loud, it reads as maturity)

The analyzer holds the owner key and can write the blocklist. In a real
deployment you'd separate those: the analyzer would only *propose* a block, and a
human or a timelock would sign it. Here it writes directly so the demo is one
command. Blocking is escalation-only, so its worst case is a refused payment; the
allow direction is the one that grants trust, which is exactly why it's gated
behind an owner yes (see "Block vs allow" above).

## File map

- `contracts/AegisGuard.sol` - the guard contract (assess, guardedPay, setters).
- `contracts/HoneypotVault.sol` - the demo villain (Parity-freeze + tx.origin).
- `contracts/MockERC20.sol` - fake USDC, tests only.
- `src/agent.js` - the stand-in agent; `main()`, `runGuard()`, and the
  owner-confirmation flow `vetThenPay()` + `confirmOwner()`.
- `src/aegis.js` - `aegisCheck`, the off-chain decision engine (3 lanes + LLM).
- `src/lanes/bytecode.js` - the real opcode scanner.
- `src/reasoning.js` - `reason()`, the LLM call (`claude -p`).
- `src/guard.js` - talks to the contract: `assessOnChain`, `guardedPay`,
  `setupGuard`, the block bridge `recordVerdictOnChain`, the allow bridge
  `allowlistOnChain`, and the `needsVetting` state check.
- `test/guard.test.mjs` - anvil-backed end-to-end tests (12 cases).

## Pointing the agent at a recipient

To pay someone I give the agent their address (and optionally an amount). Either
inline - `node src/agent.js guard 0xRecipient... 10` - or via `.env`
(`GOOD_RECIPIENT` / `BAD_RECIPIENT`) with `npm run guard-good` / `guard-bad`. An
EOA gets paid if it's clean; a first-time contract sits at REVIEW until the owner
allowlists it.

## Integrating my own agent

The real integration is one swap: the agent calls `guardedPay(recipient, amount)`
instead of `usdc.transfer(...)`. Because the enforcement is on-chain, that single
call IS the integration - the guard re-runs the policy itself and reverts if it
isn't PAY.

Setup is one-time and done by the owner: `npm run deploy-guard` then
`npm run guard-setup` (the treasury approves the guard and whitelists the agent).
The money stays in the treasury, which approves only the guard; the agent holds a
key but never funds, so it can trigger payments but can't route around the policy.

Before paying I can read the verdict for free with `assessOnChain(recipient,
amount)`, or run the full off-chain analysis with `aegisCheck(recipient, amount)`.
How I call these depends on the stack: import them straight from Node/TS, wrap
them behind a tiny HTTP endpoint for another language, or hand `guardedPay` to an
LLM agent as its "pay" tool in place of a raw transfer.

## One-paragraph summary

The agent wants to spend, so it asks the off-chain analyzer (`aegisCheck`), which
runs a real bytecode scan and, only when something looks dangerous, asks an LLM
(`reason` -> `claude -p`) to confirm. That verdict is advisory and skippable. The
binding enforcement is the on-chain guard: `guardedPay` re-runs the contract's own
`assess()` on every payment and reverts unless it's PAY, and the treasury only
ever approved the guard, so a rogue agent can't route around it. When the analyzer
confirms something is malicious, `recordVerdictOnChain` writes that into the
guard's on-chain lists (block by codehash for contracts, denylist for wallets),
so the contract blocks it by itself from then on. The bridge only tightens policy
- it can teach the guard what's bad, but only a human can teach it what's good.

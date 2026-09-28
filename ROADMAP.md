# Aegis roadmap

What is worth building next, why, and which parts of the hackathon build should
*not* be carried forward. Written 13 August 2026, after Aegis was shortlisted for
accelerator review out of the Arc Programmable Money Hackathon.

Short version: Circle now ships the blunt half of this problem as a first-party
feature, so the half worth building is the half that decides. Aegis should stop
being a second enforcement layer and become the thing that tells Circle's
enforcement layer what to enforce.

## What changed underneath the project

Circle launched **Agent Stack**: Agent Wallets, Agent Marketplace, Circle CLI,
Nanopayments powered by Circle Gateway, and Circle Skills.

The part that matters here is Agent Wallets. They natively provide time-bound
USDC spending limits, for both transfers and x402 services, plus allowlists and
blocklists over wallet and contract addresses. Those are enforced at the wallet
layer, and the wallets are MPC custodied.

Two consequences, and neither is comfortable.

**The daily cap and the address lists in `AegisGuard` are now a worse version of
a shipped product.** They were the right call during the hackathon, when nothing
else on Arc enforced them at the wallet layer. They are not something to rebuild
or defend now. The contract keeps them because the treasury rail still needs
*something* enforcing inside the transfer, but they stop being the pitch.

**The x402 signer wrap does not port to a Circle-custodied wallet.** The key is
not in the agent's process, so there is nothing to wrap and nothing to refuse
with. Against a Circle hosted wallet Aegis is advisory, exactly as the
`agent-stack-starter-kits` note in [`README.md`](README.md) already concluded.
That conclusion was written about a starter kit; it generalizes to the whole
custody model.

## Where the gap actually is

Both consequences point the same way, which is the useful part.

Circle's policy layer *enforces a judgment somebody already made*. An allowlist
or a blocklist is a record of a decision. There is nothing in it that can produce
a decision about an address nobody has looked at yet.

And an agent's job, in the world Agent Marketplace and Nanopayments are built
for, is to find and pay services it has never seen. So the load-bearing question
is not "is this address on the list". It is "this address is on no list at all,
now what".

What Circle's stack verifiably does not do:

| Surface | What it checks | What it does not |
|---------|----------------|------------------|
| Agent Wallets compliance controls | sanctions and watchlist screening | what the recipient contract actually does |
| Agent Marketplace vetting | seller payout wallets, uptime | a security review of the listed service, and nothing at all for unlisted endpoints |
| Allowlist / blocklist | an address against a prior decision | producing that decision in the first place |

That gap is the whole project. Aegis's three lanes are a risk-scoring function
over addresses Circle's policy layer has no opinion on. That is not a duplicate
feature, it sits upstream of one.

The one-line version, and the framing every part of this document should be read
against: **Circle enforces, Aegis decides.**

## The plan

Ordered so that each item either removes something the threat model already
admits is broken, or turns a documented limit into a capability. Nothing here is
a new idea bolted on; every item has a corresponding honest gap already written
down in [`THREAT-MODEL.md`](THREAT-MODEL.md) or the README.

### 1. Write verdicts into a Circle Agent Wallet, not only into our own guard

`recordVerdictOnChain` in `src/guard.js` already takes a BLOCK verdict from the
analyzer and writes it into `AegisGuard`'s own denylist and blocked-codehash
storage. The same call should be able to target a live Agent Wallet's blocklist
through Circle CLI instead.

This is a redirect of existing machinery, not new machinery. It is also the thing
that stops the custody limitation above from mattering: if Aegis cannot enforce
inside a hosted wallet, then writing the verdict into the wallet's own policy is
not a workaround, it is the correct integration.

*Done when:* a contract scored HIGH by the bytecode lane lands in a real Agent
Wallet's blocklist without a human touching the wallet, and a second wallet on
the same policy is covered without ever running the analyzer.

### 2. Kill the mock reputation lane

The reputation lane is hardcoded lists that nothing writes to. The README says so
in the lane table. It is the single most-flagged soft spot in the project and it
should not survive.

Replacing it means an actual index of recipient history rather than live
`getLogs`, which also retires the 50k-block window the behavior lane is stuck
inside and its resulting "not paid in recent history, and we will not claim
never" hedge. The hedge is correct today. It should stop being necessary.

*Done when:* a verdict cites a recipient's real payment history across every
Aegis-protected deployment, and the behavior lane can say "never" and mean it.

### 3. Point the reputation lane at discovery, not just at payment

Aegis currently starts thinking when an address is already in hand. The attack
that matters most on the x402 rail happens earlier than that.

"Five Attacks on x402 Agentic Payment Protocol" (arXiv 2605.11781) documents this
as Attack IV, server selection: an adversary shapes catalog metadata or floods a
registry with Sybil listings, and the agent is steered to an attacker-controlled
endpoint before the payment protocol begins at all. Nothing in the stack defends
this today, Circle's included.

`npm run clone-family` is already the right shape for the answer. It deploys real
EIP-1167 clones of the honeypot, blocks the codehash from one of them, and every
sibling dies with it. That mechanic pointed at Sybil listings rather than a single
scripted clone is a defense against a named, published, unsolved attack.

*Done when:* several Sybil clones of a drainer are listed, a naive selection
heuristic picks one, and one Aegis write refuses all of them, including a clone
deployed after the write.

### 4. Move the bytecode lane from scanning to simulation

The "Found and fixed" section of the threat model records three separate bypasses
of the opcode walk: a faked metadata trailer, a wide-PUSH bypass, and arithmetic
jump targets. Each was fixed by narrowing the scan.

Three rounds is a pattern, not bad luck. A linear scan infers reachability from
opcodes, and inference is what keeps getting beaten. Simulating the actual
`transferFrom` or `transferWithAuthorization` against forked state checks the real
state diff instead, which catches the class the scan structurally cannot see: a
recipient that behaves one way under `eth_call` and another way on the real
transfer.

*Done when:* a context-dependent hostile recipient passes the opcode scan and is
caught by simulation, with both runs side by side.

*Not claimed:* this closes a class of bypass. It does not make unknown contract
behavior a solved problem.

### 5. Adopt Nanopayments to close the gas hole, rather than police it

This is the largest gap in the project and the threat model is blunt about it:
gas on Arc *is* USDC, the EVM deducts it before `guardedPay`'s first opcode runs,
and a revert does not refund what was already burnt. So the agent's gas float is
a second pot that no on-chain rule can bound.

The threat model also records, in "Designs that were dropped on purpose", exactly
why the obvious fix fails: an on-chain gas-inclusive cap runs after the gas is
spent, and `tx.gasprice` is chosen by the agent anyway. That was a dead end and
was correctly abandoned.

Nanopayments through Circle Gateway are gasless. Routing the x402 float, and
settlement generally wherever Gateway supports it, does not patch the hole with a
cleverer cap. It removes the pot.

*Done when:* `npm run one-pot`, which currently demonstrates that native and
ERC-20 balance are one drainable pot, has nothing left to drain on a
Gateway-routed flow.

*Boundary:* this holds for flows routed through Gateway. Any path still touching
native gas keeps the exposure, and the roadmap should not imply otherwise.

### 6. Give `ASK_HUMAN` somewhere to go

`ASK_HUMAN` is a real verdict with no destination. It resolves as an interactive
yes or no in the same process as the agent, which the README already flags as
human-in-the-loop UX rather than a security boundary, because the owner key sits
in that process too.

The fix is the one the README names: make the owner a separate signer or a
multisig with a timelock on denylist, allowlist, codehash and cap changes, and
turn the escalation into a real quorum with an approval path, so one approver
being unreachable neither halts the agent nor quietly defaults to yes.

*Done when:* a stolen owner key cannot rewrite policy instantly, and a held
payment resolves correctly with one approver offline.

## Circle products, mapped

| Product | Where it is used |
|---------|------------------|
| **Agent Wallets** | the enforcement surface verdicts are written into (1) |
| **Circle CLI** | the integration path for writing them, and for multi-chain wallet operations |
| **Agent Marketplace** | a live source of counterparties worth assessing, and a claim to fact-check against what an x402 resource description asserts (2, 3) |
| **Nanopayments / Circle Gateway** | gasless settlement, adopted to remove the gas exposure (5) |
| **Circle Skills** | packaging the risk check so it installs into any agent framework |
| **Arc** | kept for the contract-embedded enforcement demo, which is the one thing genuinely specific to a chain where policy runs inside the transfer |
| **USDC, EIP-3009** | unchanged, still the x402 rail's payment primitive |

Keep **Circle Agent Marketplace** and the x402 **Bazaar** distinct. Different
registries, different operators. Conflating them is a factual error, not a
shorthand.

## The demo this is all pointed at

Three beats, all of them built from parts that already exist:

1. A stock Circle Agent Wallet, carrying only Circle's own policy - a spend limit
   and an empty blocklist - pays a honeypot it has never seen. Nothing triggers,
   because nothing in that policy has an opinion about an unknown address and the
   amount is under the cap.
2. Aegis scores the same address HIGH off bytecode alone, on the `HoneypotVault`
   pattern the repo already deploys, and refuses it.
3. That verdict is written into the same wallet's blocklist through Circle CLI,
   and a freshly deployed clone of the contract is refused by Circle's own wallet
   policy before Aegis is consulted a second time.

The point of this sequence is that it does not ask anyone to take a security
claim on trust. The positioning argument is the thing being watched rather than
the thing being asserted.

## Claims not to make

The project's existing discipline about `AegisAuditLog` - that it proves a
reporter said something, not that anything was stopped - should extend to
everything below.

- Aegis does not stop prompt injection. It stops a compromised agent from moving
  money. The README gets this right and the pitch should not drift off it.
- A reputation lane raises the cost of Sybil and fake-merchant attacks. It does
  not solve them, and a feed built from self-reported verdicts has a bootstrap
  problem of its own that should be stated rather than grown out of quietly.
- Simulation closes a class of static-analysis bypass, not the general problem.
- Gateway removes the gas exposure on Gateway-routed flows only.
- None of this is a finding against Circle. It is a layer their stack does not
  cover, and the difference in tone matters.

## Open questions

Unresolved at the time of writing, and load-bearing enough that they should be
answered before anything in section 1 is promised as built:

- Does the Agent Wallets policy engine expose an external callout or webhook for
  a pre-transaction decision, or is the only integration path writing addresses
  into the blocklist after the fact? The current docs did not settle this. If the
  hook does not exist, that is worth raising directly rather than designing
  around silently.
- Where does Gateway settlement actually reach today, and does the treasury rail
  fit through it or only the x402 float?
- How much of the reputation index can be honest with a single deployment's data,
  and what is the smallest trusted set that makes it mean anything?

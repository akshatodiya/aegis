# Aegis: A Firewall for AI Agents on Solana

An AI agent with a wallet is one bad payment request away from losing funds. Aegis checks **who is getting paid** and answers **PAY**, **BLOCK** or **ASK_HUMAN** before the payment leaves. It enforces at the last point where that payment can still be stopped: inside the treasury transfer on one rail, and before the x402 wallet signs on the other. The guard is deployed on Solana devnet at `CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6`, and all five demo beats have run there with Circle's devnet USDC (2026-10-15). The automated tests run on a local validator. No x402.org interoperability result is claimed.

## Status

- **Live on Solana devnet.** Program [`CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6`](https://explorer.solana.com/address/CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6?cluster=devnet), with a vault funded with Circle's devnet USDC.
- **All five demo scenarios ran on devnet** (2026-10-15): a clean payment, a recipient with an attacker delegate, a look-alike USDC over x402, an injected agent that skips Aegis, and the owner's kill switch. Every result is a public transaction.
- **All tests pass:** 343 TypeScript tests (278 unit tests on fake chains, 65 on a local validator) and 8 Rust unit tests for the program's spending cap.

## Two payment rails

```text
Agent request
  |-- treasury USDC --> aegisCheck --> aegis_guard.guarded_pay --> recipient
  |                                      on-chain policy + daily cap
  `-- HTTP 402 -------> fetch wrapper --> guarded signer -------> merchant
                        catalog, price,   exact bytes, chain state,
                        human approval    aegisCheck, simulation
```

**Treasury.** The Anchor program `aegis_guard` holds classic SPL USDC in a PDA-owned vault. `guarded_pay` requires an agent entry, checks deny and blocked-program entries, the recipient and destination token account, and a daily cap before an atomic transfer. It rejects frozen, reassigned or delegated destinations according to its policy. The owner can revoke an agent or withdraw from the vault. A reporter can write an on-chain refusal receipt; that receipt records a decision but does not enforce one.

**x402.** A service returns HTTP 402 with a Solana payment request. The fetch wrapper checks the catalogued payee and HTTP origin, posted price, pinned USDC and any human approval. The signer decodes the exact transaction bytes it will sign, checks the pinned RPC and recipient through `aegisCheck`, then simulates the payment and checks the balance changes. A refused payment is never signed. The x402 wallet has zero SOL and receives its limited USDC float only through `guarded_pay`; the merchant in this repo pays transaction fees as its own facilitator. The on-chain guard sees the **refill**, not the later x402 merchant payment.

The shared screening engine has three lanes: **inspection** reads accounts, token destinations, programs and mint controls; **behavior** reads the guard's per-recipient payment stats; **reputation** has the same interface but currently uses mock data. The order is denylist → HIGH fact blocks → unreadable chain state or a MEDIUM fact asks a human → unusual amount asks a human → PAY. An optional `claude -p` pass explains typed facts; HIGH facts still block deterministically. The demo skips the model. For the complete payment flow, see the [architecture document](docs/architecture.md) or its [PDF](docs/architecture.pdf); [DESIGN.md](DESIGN.md) has the exact rules and codes.

## Quick start

Use Node 26, Yarn, Anchor 1.2.0 and the already-installed Solana 4.1.2 release. Anchor 1.2 builds SBPF v3, which the older 3.1 validator cannot load. `scripts/with-toolchain.sh` selects Solana 4.1.2 for commands that need it without changing the global CLI. The build and test scripts already use that wrapper and the legacy validator.

```sh
yarn install
yarn build
yarn test
yarn test:unit
```

For a local demo, start with fresh project keys in gitignored `keys/deployer.json`, `keys/owner.json` and `keys/agent.json`. In one terminal:

```sh
yarn build
sh scripts/with-toolchain.sh anchor localnet --validator legacy --skip-build
```

In another:

```sh
export AEGIS_RPC_URL=http://127.0.0.1:8899
export AEGIS_PROGRAM_ID=CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6
yarn demo:setup
yarn demo all
```

Setup reads state and fills only what is missing. `yarn demo <good|delegated|bad-mint|drain|kill>` runs one beat; run `delegated` before `drain`.

## Five demo beats

1. **Good recipient:** Aegis says PAY; a guarded transfer moves exactly 1 USDC from the vault to a clean wallet.
2. **Delegated recipient:** an attacker delegate is visible before payment; the bridge records a deny entry, and a rerun writes nothing.
3. **Bad mint over x402:** a Token-2022 look-alike offers “USDC” with a permanent delegate and freeze authority; the wrapper refuses `NO_PAYABLE_OPTION` and logs a receipt.
4. **Injected drain:** an agent skips the off-chain check and calls `guarded_pay` at the denied recipient; the transaction lands failed and the vault does not move.
5. **Kill switch:** the owner revokes the agent; the same clean payment fails on-chain with `NotAgent`, then the script restores and rereads the agent entry.

Each beat returns structured results and prints short text plus Explorer links for its transactions.

## What is real, and what is not yet demonstrated

| Part | Local validator | Devnet status |
|---|---|---|
| Treasury rail | Real Anchor instructions, PDA vault, classic SPL token transfers, list entries, cap and failed transactions | Deployed; `guarded_pay`, the deny entry, the on-chain drain refusal and the kill switch ran in the demo (2026-10-15) |
| USDC | A **test mint** placed at Circle devnet USDC's address by `Anchor.toml`; no Circle funds | Circle's classic devnet USDC from faucet.circle.com, moved into the vault by hand; setup never mints there |
| x402 | Real HTTP 402, signed v0 payment and settlement tests with our merchant acting as its own facilitator; the bad-mint demo refuses before signing | The bad-mint refusal and the float refill through `guarded_pay` ran on devnet. A successful x402 settlement on devnet, an x402.org check and a third-party facilitator have not been run |
| Inspection and behavior | Real chain reads; behavior uses guard stats from actual `guarded_pay` transfers | Ran on devnet in the demo, against real devnet accounts and mints |
| Reputation and LLM | Reputation is a mock; `claude -p` is optional and skipped in the demo | Same limitations |
| Refusal receipts | Real `log_refusal` transactions, separate from the payment refusal | A receipt was written on devnet in the bad-mint beat |

The TypeScript test files define **343 tests: 278 unit cases on fake chains and 65 cases on a local validator**, and all of them pass with `yarn test` (last run 2026-10-15). The local validator suite includes every demo beat; the program also has 8 Rust unit tests for its spending cap, which pass with `cargo test`.

## Security model and limits

A prompt-injected agent can ignore advice and try to pay directly. It cannot move USDC out of the treasury vault without passing `guarded_pay` while it has only the agent key. It cannot make the x402 signer approve a payment outside that signer's checks while its payment key is held behind the signer. A process that can read the underlying key, or a hosted wallet that lets the agent bypass this signer, breaks that x402 boundary. The owner can withdraw without the cap, and the upgrade authority can replace the program; both keys are roots of trust. The delegated beat loads the owner key to write a deny entry; the drain and x402 agent processes do not. See [MIGRATION.md](MIGRATION.md) and [DESIGN.md](DESIGN.md) for the threat model.

Known limits:

- Devnet x402.org interoperability and settlement through an independent facilitator are untested. The demo merchant's replay map is in process; after a restart it checks a known transaction signature on-chain when simulation rejects a replay, subject to RPC availability. A streaming 402 body has a byte limit, but its caller still needs a request deadline.
- The signer enforces transaction shape, chain checks and recipient policy. Catalog entries, posted prices and human approval live in the fetch wrapper; handing an agent the signer alone loses those wrapper checks.
- The catalog trusts one HTTP origin per payee, not individual paths. A service controlling that origin can demand any payment up to its listed price. A signed retry does not follow redirects.
- The merchant sponsors settlement fees. Its compute limit is capped at 40,000 and its compute price is capped, but repeated distinct valid payments still consume merchant SOL; there is no per-client rate limit.
- The demo merchant prepares its `product` response before settlement. That callback must only prepare data in memory: an email, webhook or inventory change there could happen without payment if settlement fails. The response is sent only after settlement confirms.
- A delegate is checked from chain state before or during a payment. A delegate added **after** receipt can still sweep the recipient's USDC. The guard's daily cap bounds treasury outflow, not the agent's SOL fees or rent; spending on both sides of a day boundary can use two days' caps quickly.
- The x402 float bounds immediate loss to its current balance and sustained refill to the daily cap, not lifetime loss. Stopping refills and rotating the float key is the x402 kill switch; revoking the treasury agent does not reclaim an existing float.
- Demo setup requires 3 USDC of remaining daily allowance for the default beats. That check is a snapshot; another agent can spend the allowance before the demo runs.
- The kill-switch beat restores the agent in a `finally` block, but a process crash or RPC outage can leave it revoked. `yarn demo:restore-agent` is the manual recovery path and confirms the entry by reading the chain.
- Behavior uses all-time guard stats, not x402 history. In-cap payments can raise its 5× anchor (50 → 250 → 1250 USDC) without review; with complete history it never decays. The daily cap is the hard bound.
- The look-alike check covers common Cyrillic and Greek characters and fullwidth forms, not the full Unicode confusables table. Metaplex metadata for classic mints is not read. Seller descriptions are untrusted text, even after display cleaning.
- An empty audit log proves nothing. A permitted reporter can write a refusal receipt without having stopped a payment. RPC failures can prevent analysis or receipt readback, and incomplete simulation balance evidence prevents signing; an unknown chain result must be checked before retrying.

## Repository map

| Path | Role |
|---|---|
| `programs/aegis_guard/` | Anchor guard, policy, state and events |
| `src/aegis.ts`, `src/lanes/` | Decision order and the three screening lanes |
| `src/guard/`, `src/float.ts`, `src/audit.ts` | Client, bridge, float refill and refusal logger |
| `src/x402/` | Wire codec, signer, fetch wrapper and demo merchant |
| `src/demo/`, `scripts/` | Structured demo beats, formatter, setup and CLI |
| `tests/` | Live validator tests, fake-chain unit tests and local-only fixtures |
| `docs/` | Architecture document and diagram |

The detailed design and remaining work are in [DESIGN.md](DESIGN.md).

## License

All rights reserved. No license is granted to copy, modify or reuse any part of this repository; see [LICENSE](LICENSE).

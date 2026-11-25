# Aegis on Solana: migration map

This is the port of `../aegis` (Arc, EVM) to Solana devnet. Facts were checked on 2026-09-29.
How each piece gets built (on-chain check order, signer checks, test plan) is in `DESIGN.md`, which records steps 2 to 6. This file covers the what and the why.

## Map

| Arc / EVM | Solana | Notes |
|---|---|---|
| `AegisGuard.sol` | Anchor program `aegis_guard` | |
| treasury EOA + `approve(guard)` | **PDA vault**: the USDC ATA owned by the program's `config` PDA | See Custody below. |
| `isAgent`, `denylisted`, `allowedContract` mappings | one PDA per entry, `[kind, config, key]` | An entry counts only if the program owns it and it holds entry data. An account that only holds lamports (anyone can send them) counts as absent. |
| `blockedCodehash` | `blockprog[program_id]` | Blocks every recipient whose data that program owns, and survives upgrades. A PDA that only *signs* for a token account usually has no data, so it reads as System-owned. The allow entry for such a PDA records its controlling program, so a later block still overrides the allow, as `blockedCodehash` overrode `allowedContract`. Escape: redeploy under a new program id. |
| `code.length > 0` → must be vetted | recipient is off-curve (a PDA) or owned by a non-System program | The on-curve check is a syscall, about 190 CU. Programs, mints, token accounts and sysvars as recipients are BLOCK: funds sent there are stranded. |
| (none) | destination token account checks | The account must be **owned by the recipient**: on classic Token an ATA's owner can be reassigned, so the address proves nothing. It must not be frozen. A live delegate means REVIEW, because the delegate could sweep what we pay. Enforced on-chain on the treasury rail, and in the signer on x402. |
| `dailyLimit`, `spentOnDay` | `daily_limit`, `current_day`, `spent_today` in config | *Changed on purpose:* `0` now means frozen, and there is an explicit `paused` flag. On EVM, `setDailyLimit(0)` turned the cap off, a documented footgun. |
| `assess()` view | `assess(amount)` read-only instruction, called via `.view()` | Same `evaluate()` as `guarded_pay`, so the verdicts agree for the same state. A read needs a funded fee-payer address but no signature. |
| `guardedPay` + `Paid` | `guarded_pay`: checks → `transfer_checked` signed by the PDA → `emit_cpi!(Paid)` | Self-CPI events can't be forged and are less exposed to log truncation. A revoked agent still fails first, with `NotAgent`. |
| two-step ownership | same | New: `initialize` is gated to the upgrade authority, which closes the init front-run. |
| `AegisAuditLog` | `log_refusal` in the same program, reporter PDAs, event + counter | Same rules: Block/AskHuman only, 1–256-byte reason, 1-based ids. *Changed:* the refusal code gets its own field instead of a prefix on the reason. |
| bytecode lane | **inspection lane**: account data, not code | What the recipient is and who controls it (upgrade authority, last deploy), plus the destination token account. For a non-USDC asset it also checks the mint's Token-2022 extensions. Decode or RPC errors fail closed. |
| behavior lane (50k-block window of `Paid` logs) | stats PDA `{count, largest, total}` written by `guarded_pay` | All-time, one read, writable only by the program. Same 50 USDC / 5x rule. |
| reputation lane (mock) | same | |
| LLM second pass (`claude -p` over bytecode) | same CLI, over typed account facts | It sees the lane's facts, not program code, so it explains rather than independently confirms (see decision 7). |
| x402 EVM `exact` (EIP-3009 typed data) | x402 SVM `exact` v2: partially signed v0 tx `[CU limit, CU price, TransferChecked, Memo]`; the facilitator pays fees | The spec now lives at `x402-foundation/x402`. Network `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`. USDC `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU` (classic Token, 6 decimals). |
| signer wrapping `signTypedData` | locally typed signer with kit-compatible `signTransactions`; `signMessages` accepts only an off-chain domain | It decodes the exact message, pins mint, source, destination owner, amount and instruction list, refuses to be fee payer, checks the blockhash on the pinned RPC, and simulates. Raw transaction-shaped messages cannot use `signMessages`. |
| fetch wrapper (catalog, posted price, per-payment cap, `cleanText`, ASK_HUMAN) | ported | Addresses compare case-sensitively (base58). Each catalog payee is tied to an HTTP origin. The v2 reply now includes the required `accepted` field, which the Arc build omitted. |
| mock merchant (verifies, never settles) | the merchant is its own facilitator and settles on the local validator | It verifies with its own web3.js decoder. `@x402/svm` is not installed, and no devnet or third-party facilitator settlement has been run here. |
| JIT float via `guardedPay` | same | The float wallet needs **0 SOL**. "Signs, never sends" is now enforced. |
| refusal codes | same vocabulary, adapted | Examples: `BLOCKED_CODEHASH` → `BLOCKED_PROGRAM`; `WRONG_CHAIN` → `WRONG_NETWORK`; `*_BYTECODE` → `*_RISK_ACCOUNT`. Anchor and token-program error numbers map onto codes, and anything unrecognized is `UNKNOWN`. |
| viem, solc, anvil | `@anchor-lang/core` 1.2 for the program, `@solana/web3.js` and `@solana/spl-token` for the client and x402, `anchor test --validator legacy` | The signer implements a kit-compatible shape locally; `@solana/kit` is not installed. Tests put a local mint at the devnet USDC address, so nothing needs devnet. |

**Custody.**
- **Why not a delegate.** A delegate on the treasury's token account is the literal port, but on Solana:
  - the treasury key could still transfer directly, bypassing policy;
  - a token account has one delegate slot, and any other `Approve` evicts the guard;
  - the allowance runs out and must be re-approved.
- **What the vault means.** With a PDA vault, only the program moves funds: `guarded_pay` (capped) and an owner-only `withdraw`. The treasury key and `rotate-keys` go away.
- **What it costs.** The **upgrade authority becomes a root key**: it can drain the vault. The **owner is effectively the treasury key**, since `withdraw` is uncapped.
- **Assets.** Classic-Token mints only for now. A Token-2022 mint with a permanent delegate could empty the vault without calling Aegis.

## Dropped

- **The opcode walk and its 13 tests.** That covers the CBOR metadata trim, reachability proofs, `HIDDEN_CODE` and minimal-proxy detection. There is no bytecode to scan.
- **EVM-only mechanics:**
  - EIP-7702;
  - EIP-3009 and EIP-712 domain pinning, `validAfter`/`validBefore`, `Receive`/`CancelAuthorization`;
  - EIP-55 checksums (Solana addresses have none).
- **"One pot, two windows."** Fees are SOL, so the guarded USDC can't be burned as gas. The agent's own SOL float is still burnable, fees are charged even on failed transactions, and that stays a limitation.
- **Custody machinery:** `setTreasury`, `rotate-keys`, `treasury-approve`.
- **Direct pay and approve (`good`/`bad`, `EOA_ALLOWANCE`).** The agent holds no USDC to pay or approve from.
- **Arc toolchain:** solc, Etherscan verification, the Sepolia fallback, Arc gateway rotation.
- **Deferred, not dropped:** `web/check.html`, `sell-demo`, `clone-family`.

## New on Solana (goes into the threat model)

- **Who holds power:**
  - The program's **upgrade authority** is a total-compromise key.
  - `initialize` is gated to it.
  - Key roles are split: deployer, owner, agent, float, merchant.
- **Caller-chosen accounts.** Every account passed to an instruction is chosen by the caller. The program derives every PDA itself, requires deny and blockprog accounts at their canonical addresses, and pins the vault, mint and token program.
- **Classic-Token recipient risks:**
  - ATAs can change owner;
  - recipient accounts can carry a sweeping delegate or be frozen.
- **Rent griefing.** A missing ATA (about 0.0015 SOL) or a new stats PDA (about 0.001 SOL) is paid from the agent's SOL. The USDC cap doesn't bound that.
- **x402:**
  - durable nonces;
  - raw `signMessage` can sign a transaction;
  - a 402 can name us as fee payer;
  - the seller's memo is signed into our transaction;
  - lookup tables can hide accounts.
- **Issuer powers.** Circle's live freeze authority can freeze the vault.
- **Time and history:**
  - Clock skew is seconds to minutes, and the 2x burst at midnight remains.
  - Events have no indexed topics.
  - History depends on how long the RPC retains it.
  - Daily rollover can't be driven on the test validator, so it is a Rust unit test.
- **Carried over unchanged:**
  - the x402 float bounds the loss *rate*, not the total;
  - the on-chain lists never see the x402 merchant;
  - owner compromise is total; the bridge process loads the owner key for list writes, while the drain and x402 agent processes do not;
  - an empty audit log proves nothing, and a reporter can forge entries;
  - reputation is a mock;
  - the 5x anchor ratchets without review (50 → 250 → 1250), and complete history means it never decays;
  - seller text can lie;
  - with a hosted wallet, Aegis is advisory.

## Decisions

Answered 2026-09-30: **all defaults** (the bold option in each row).

| # | Question | Options |
|---|---|---|
| 1 | Custody | **PDA vault** / delegate |
| 2 | Owner key | **only in admin/bridge scripts, never in the drain or x402 agent process** / one key for everything, like the Arc demo |
| 3 | Behavior history | **stats PDA** (agent pays ~0.001 SOL per new recipient) / scan events |
| 4 | `daily_limit = 0` | **frozen, plus a `paused` flag** / keep EVM "off" |
| 5 | Demo villains | **treasury rail:** a recipient whose USDC account has an attacker delegate (REVIEW, then the bridge writes BLOCK). **x402 "bad mint":** a Token-2022 look-alike USDC with a permanent delegate; refused as `NO_PAYABLE_OPTION`, and the lane prints what that mint can do. The `initialize` refusal is shown in tests only. |
| 6 | Seller `extra.memo` (signed on-chain, verbatim by spec) | **sign only 1–64 chars of `[A-Za-z0-9_.:-]` (an invoice id), else refuse** / refuse any 402 that sets a memo |
| 7 | LLM role | **analyze-only: HIGH facts BLOCK deterministically** (they are exact reads, not an over-approximating opcode scan) / keep the EVM "LLM can downgrade HIGH to ASK_HUMAN" |
| 8 | Missing recipient ATA (treasury rail) | **`guarded_pay` requires it; the client creates it only for on-curve wallets** / `guarded_pay` creates it |
| 9 | x402 settlement | **the merchant acts as its own facilitator** / x402.org only. Local-validator settlement is tested; the devnet and x402.org runs remain open. |
| 10 | Refusal log | **in `aegis_guard`** (one deploy; it shares the upgrade authority) / its own program |

# Aegis on Solana: design notes

Implementation detail for steps 2 to 6. `MIGRATION.md` is the short version to review. This file records how each piece gets built, and why.
Facts were checked on 2026-09-29 against:
- devnet (solana-core 4.3.0);
- the Anchor 1.2.0 sources;
- p-token (the classic Token program, live since SIMD-0266 and bundled in the 4.1.2 test validator);
- Token-2022 10.0;
- the `x402-foundation/x402` spec and `@x402/svm` 2.27.

Rent figures are devnet rates on that date. Code reads `getMinimumBalanceForRentExemption` and never hard-codes them.

## Keys

Every key is a fresh devnet keypair in `keys/`, which is gitignored. `Anchor.toml` `[provider] wallet` points there, never at `~/.config/solana/id.json`. Nothing is copied from `../aegis`.

| role | signs | holds |
|---|---|---|
| deployer (upgrade authority) | `anchor deploy`, `initialize` | SOL for deploys |
| owner | setters, `withdraw`, bridge writes, kill switch | a little SOL |
| agent | `guarded_pay`, `log_refusal` (reporter) | a SOL float for fees and rent, no USDC |
| float | x402 payments only | the USDC float, **0 SOL** |
| merchant | the demo merchant's payTo and fee payer | SOL for fees when it settles a payment |

Three keys can move vault funds:
- the agent, through policy and the cap;
- the owner, through `withdraw`, uncapped;
- the upgrade authority, which can do anything.

A process that loads the owner key can empty the vault. The README says which scripts load which key.

## Program `aegis_guard`

**Crate features:**
- anchor-lang 1.2.0: `["event-cpi", "init-if-needed"]`.
- anchor-spl 1.2.0: token and associated_token.
- `idl-build = ["anchor-lang/idl-build", "anchor-spl/idl-build"]`.

**Classic Token only.** `initialize` requires the mint's owner to be `TokenkegQ…`. Token-2022 is deferred. If it is ever enabled, `initialize` must refuse all of the following, because each lets the issuer bypass or brick the vault, `withdraw` included:
- PermanentDelegate;
- any TransferHook extension, even one with only an authority set;
- TransferFee, Pausable, NonTransferable and DefaultAccountState.

### State

| account | seeds | fields |
|---|---|---|
| Config | `[b"config"]` | `owner`, `pending_owner: Option<Pubkey>`, `mint`, `vault`, `daily_limit`, `current_day: i64`, `spent_today`, `paused`, `pay_count`, `bump` |
| AuditLog | `[b"audit", config]` | `total_refusals`, `bump`. Kept separate from Config so refusals don't write-lock `guarded_pay`. |
| Entry | `[kind, config, key]`, kind ∈ `agent`, `deny`, `allow`, `blockprog`, `reporter` | `bump`. `allow` entries also store `controller: Pubkey`, the program that signs for a PDA recipient; it is the default key when not applicable. |
| Stats | `[b"paid", config, recipient]` | `count`, `largest`, `total`, `bump`. Written only by `guarded_pay`. |
| Vault | ATA(config, mint, Tokenkeg) | Address recorded in Config at `initialize`, and checked to have no delegate and no close authority. |

**Membership rule, for every list.** An entry counts only when an account at the **canonical-bump** PDA is:
1. owned by `aegis_guard`; and
2. carrying the `Entry` discriminator.

Anyone can send lamports to any address. So an account holding lamports but owned by System is **absent**: not an agent, not denied, not allowed.

Negative checks (`deny`, `blockprog`) are **required** `UncheckedAccount`s at `seeds = [...], bump`. A caller can't skip one by leaving it out, and can't dodge it with a non-canonical bump. Tests pre-fund each of these PDAs and assert the verdict does not change.

### Instructions

- **`initialize(owner, daily_limit)`**
  - Signer must be the program's upgrade authority: `program.programdata_address() == Some(program_data.key())` and `upgrade_authority_address == Some(signer)`. This closes the init front-run.
  - Tests need `[test] upgradeable = true` in `Anchor.toml`. The default `--bpf-program` load sets the authority to `111…1`, so `initialize` would always fail.
  - The vault ATA is `init_if_needed`: anyone can create the config PDA's ATA first, and that must not brick `initialize`. The handler then checks its owner is config and that it has no delegate and no close authority.
  - A Token-2022 mint is refused by `Account<Mint>`'s owner check (`AccountOwnedByWrongProgram`).
- **Owner-only setters:**
  - `add_entry(kind, key, controller)` and `remove_entry(kind, key)`, with `kind` ∈ Agent, Deny, Allow, BlockProgram, Reporter. Add uses `init_if_needed`, so it is idempotent (like the EVM setters) and works on a pre-funded address. Remove closes the entry back to the owner. `controller` is stored for Allow only. *(Built this way in step 2 instead of five `set_*` pairs; the client helpers wrap it.)*
  - `set_daily_limit`, `set_paused`.
  - `transfer_ownership(Option<Pubkey>)` plus `accept_ownership`.
  - `withdraw(amount)`: emits `Withdrawn` and works while paused.
- **`guarded_pay(amount)`**
  - The Accounts struct only pins addresses: config, vault = `config.vault`, mint = `config.mint`, token program = Tokenkeg, event authority.
  - Everything policy reads is an `UncheckedAccount`: destination, recipient, and the agent, deny, allow and blockprog entries.
  - Agent, deny and allow entries are pinned by `seeds, bump` (canonical). The two blockprog accounts depend on account data (the recipient's owner, the allow entry's controller), so `evaluate()` derives and checks them itself: a wrong address is `BadEntryAccount`. `blockprog_controller` is optional and required only when the allow entry names a controller (`MissingControllerEntry`).
  - The handler calls `evaluate()` and gets typed errors in the order below. It does **not** use Anchor constraints, which would fire first with framework error codes; that would break "revoked agent → `NotAgent`".
  - The stats PDA is `init_if_needed` (the agent pays). Any refusal reverts it with everything else.
- **`assess(amount) -> Assessment`**
  - Its own all-read-only Accounts struct, which `.view()` requires. It runs the same `evaluate()` and returns the verdict as an **Ok value** (under 1 KB), never as an error.
  - The day rollover is computed but not written.
  - It agrees with `guarded_pay` for the same state. It can still differ from an actual pay: vault balance, the agent's SOL, and any change between the preview and the send are outside `evaluate()`.
  - A `.view()` call simulates, so it needs the address of a funded fee payer but no signature.
- **`log_refusal(recipient: Option<Pubkey>, amount, verdict: {Block, AskHuman}, code, reason)`**
  - Gated to reporters.
  - Reason is 1–256 bytes; code is ≤32 bytes of `[A-Z_]`.
  - Borsh rejects any other verdict byte, so a PAY cannot be recorded.
  - `id = total_refusals + 1`, then `emit_cpi!(Refused)`. The log touches no vault account. It shares the vault's program and upgrade authority; that is a deliberate trade against a second deploy.

### `evaluate()`: the order

Deny runs before allow. The agent check comes first, so a revoked agent is refused before any policy runs. It lives in `guarded_pay`, not in `evaluate()`: `assess` takes no agent (as on EVM), which is what lets "revoked agent refused while `assess` says PAY" hold.

1. Agent entry is a member (see the membership rule), else **`NotAgent`**. *(`guarded_pay` only.)*
2. `paused` → **REVIEW `Paused`**.
3. `amount == 0` → **`BadAmount`**.
4. Recipient is one of: the default key, the incinerator `1nc1nerator…`, config, vault, audit, or any account owned by `aegis_guard` → **BLOCK `SinkRecipient`**.
5. Deny entry is a member → **BLOCK `Denylisted`**.
6. Classify the recipient by `AccountInfo.owner`. Never by `executable` (SIMD-0162 is active), never by the curve.

   | owner | verdict |
   |---|---|
   | a loader (BPFLoaderUpgradeable, BPFLoader2, BPFLoader1, LoaderV4, NativeLoader). This covers programs, ProgramData and Buffers | **BLOCK `ProgramRecipient`** |
   | Tokenkeg or Token-2022 (a mint, token account or multisig) | **BLOCK `TokenAccountRecipient`** |
   | Sysvar | **BLOCK `SysvarRecipient`** |

   None of these can be allowlisted.
7. Program-controlled means `!is_on_curve(recipient)` (the syscall costs about 190 CU) **or** an owner other than System:
   - Owner ≠ System and `blockprog[owner]` is a member → **BLOCK `BlockedProgram`**.
   - An allow entry is a member and `blockprog[allow.controller]` is a member → **BLOCK `BlockedProgram`**. A program block therefore still wins over a PDA that was allowlisted earlier. That matters because a data-less PDA, the usual token authority, reads as System-owned.
   - An allow entry is a member → continue.
   - Otherwise → **REVIEW `UnvettedProgramRecipient`**.
8. Destination token account checks:

   | condition | verdict |
   |---|---|
   | not owned by Tokenkeg, not 165 bytes, uninitialized, or mint ≠ `config.mint` | **BLOCK `BadDestination`** |
   | `owner ≠ recipient` | **BLOCK `DestinationOwnerMismatch`**. Classic Token lets an ATA's owner be reassigned, so the address proves nothing |
   | frozen | **BLOCK `FrozenDestination`** |
   | `delegate` set with `delegated_amount > 0` | **REVIEW `DelegatedDestination`**. The delegate could sweep what we pay |

9. Cap:
   - Roll the day in memory: `unix_timestamp.div_euclid(86400)`. It only rolls forward: if the clock ever reads an earlier day, today's spend is kept, not reset.
   - `daily_limit == 0` → **REVIEW `DailyCap`** (frozen).
   - `spent.checked_add(amount)` overflows or exceeds the limit → **REVIEW `DailyCap`**.
10. **PAY.** Book the spend, CPI `transfer_checked` signed by the config PDA, update stats with `checked_add`, then `emit_cpi!(Paid {id, agent, recipient, destination, amount, day, spent_today})`.

### Events and receipts

**Why `emit_cpi!`, not `emit!`:** logs are capped at 10 KB per transaction, and data providers may truncate them. Self-CPI event data can't be forged, because only this program can sign for `__event_authority`, and it is less exposed to truncation. CPI events can't be subscribed to.

**Reading events back:**
1. `getSignaturesForAddress(config | audit)`, paginated.
2. `getTransaction` for each signature; skip any with `err != null`.
3. Decode every inner instruction to this program that starts with the event tag.
4. Readback says "complete" only when the ids found equal `pay_count` / `total_refusals`.

**Treasury-rail refusals:** an Anchor error reverts the transaction. The drain demo sends with `skipPreflight: true`, so the failed transaction lands and is visible on Explorer. Every write checks `meta.err`, or goes through `.rpc()`, which throws on it. A transaction that landed but failed is never printed as done.

### Tests (step 2)

- **Harness:**
  - `anchor test --validator legacy`, with `[test] upgradeable = true`.
  - `[[test.validator.mints]]` puts a classic 6-decimal mint at the devnet USDC address, `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, with test mint and freeze authorities. The same pinned constant then works everywhere, and the frozen-destination path is testable.
  - No test touches devnet.
- **Day rollover** can't be driven on `solana-test-validator`: `warp_slot` applies only at startup. It is covered by a pure Rust unit test of the cap function, which takes `now` as an argument. Cases: same day, next day, a skipped day, and the 2x burst at midnight. Host tests that reach `is_on_curve` enable the `curve25519` feature.
- **Ported from `guard.test.mjs` and `audit-log.test.mjs`:**
  - PAY
  - denylist
  - unvetted → REVIEW
  - allowlist flips REVIEW to PAY
  - not an agent
  - revoked agent refused while `assess` says PAY
  - restore
  - daily cap
  - float refill draws on the cap
  - owner-only setters
  - two-step ownership
  - the "zero address" case (now `SinkRecipient`)
  - reporter gate
  - consecutive ids
  - empty reason, 256 bytes accepted, 257 bytes refused
  - PAY cannot be logged
- **New:**
  - pre-funded deny, allow and agent PDAs don't change the verdict
  - reassigned-owner ATA → BLOCK
  - delegate → REVIEW
  - frozen → BLOCK
  - program, ProgramData, mint, token account and sysvar recipients → BLOCK
  - PDA → REVIEW, then allowed → PAY
  - blocking the controller overrides allow
  - paused
  - `daily_limit = 0` freezes
  - initialize: gate, classic-only, vault state
  - `withdraw` is owner-only
  - Paid and Refused events decode

**Step 2 status (2026-09-30):** every case above is in `tests/aegis_guard.ts` (30 tests), plus 8 Rust unit tests of `check_cap` in `policy.rs`. Also covered: a pre-created vault ATA doesn't brick `initialize`; deny beats allow; an allow entry doesn't beat a block on the owning program; a wrong blockprog address is `BadEntryAccount`; a missing controller account is `MissingControllerEntry`; a destination for another mint is `BadDestination`. Harness notes: mocha 9's yargs fails under Node 26, so the suite runs on mocha 11 + ts-mocha 11 + ts-node; test-only mint authority is `tests/fixtures/mint-authority.json` (localnet only, never funded on devnet).

## Inspection lane (step 3)

**The fetch.** One `getMultipleAccounts` call, base64 encoding, for: the recipient, ATA(recipient), the owner program's ProgramData (`dataSlice` 45 bytes), and the mint if it isn't USDC.

**Three states, as in EVM.** An RPC error means **unknown**, which leads to ASK_HUMAN. It is never read as "no account, fresh wallet". Decode errors and unknown Token-2022 extension types also fail closed.

| level | facts |
|---|---|
| HIGH | the recipient is a program, ProgramData, mint, token account or sysvar; destination owner mismatch; frozen destination; a delegate allowed at least the amount; the owning program is closed or retracted, or is not a real program (missing, not executable, or the account names itself as owner); the program is blocked on-chain; any mint other than USDC (Aegis only pays USDC; the mint's own findings are shown for information), and for such a mint a permanent delegate, "USDC" metadata (look-alike letters from other scripts included), or an unknown extension |
| MEDIUM | off-curve recipient whose controller no allow entry names (its data owner is not proof); program-owned recipient whose program is upgradeable or was recently deployed, reporting the authority and last deploy slot; destination delegate below the amount; ATA missing, so we would fund rent (lamports alone at the ATA address count as missing); a mint whose metadata lives in another account |
| LOW | on-curve System wallet (whether or not the account exists); keypair address whose data an immutable program owns; off-curve recipient allowlisted with an immutable controller |

- **Registry.** A known-program registry names programs instead of zeroing them, the same idea as `CIRCLE_SYSTEM`. It covers System, Token, Token-2022, ATA, Memo, ComputeBudget, the loaders, Squads v4 and CCTP v2. Registry programs are never written to `blockprog`.
- **Fingerprint.** The ELF hash is taken with trailing zero padding trimmed and the program's own id zeroed, because Anchor programs embed their id. It is a clustering signal for `blockprog` writes, not proof.
- **`aegisCheck` order** (same as EVM, except step 2 follows the default for decision 7):
  1. Denylist → BLOCK.
  2. HIGH → BLOCK, with no LLM downgrade. Decision 7 in `MIGRATION.md` keeps this deterministic on Solana.
  3. MEDIUM → LLM analyze, then ASK_HUMAN.
  4. Unusual amount → ASK_HUMAN.
  5. Otherwise PAY.
- **LLM input** is typed facts only. Free text (token metadata, memo) is cleaned by `cleanText`, capped at 64 characters, and fenced as untrusted. `claude -p` runs with no tools, and its answer is labelled as model output.
- **Bridge** (`recordVerdictOnChain` / `vetThenPay`):
  - BLOCK writes happen automatically, after reading the exact PDA first for idempotency.
    - Wallets and PDAs that have no account go to `deny`.
    - Program-owned recipients get their owner written to `blockprog`, unless the owner is System, Token, Token-2022, ATA, a loader or a registry program.
  - ALLOW is never automatic:
    1. The owner answers y/N, and no TTY means no.
    2. The `controller` is recorded.
    3. The assessment is re-read, and payment happens only on PAY.
  - Allow is not offered for a PDA whose controller can't be identified.

**Step 3 status (2026-10-01):** built, then reviewed adversarially and fixed. Unit tests (`tests/unit/*`) run on a fake chain; `tests/lanes.ts` runs the lanes, the client and the bridge against the local validator. Deltas from the plan above:
- **Who controls the USDC, not who owns the data.** A program-owned recipient on the curve is judged by its data owner (the guard checks `blockprog[owner]`), but a keypair signs for its USDC account, so no program is named as its controller. Off the curve, only the deriving program can sign, and it can assign the data to any program (an immutable one, to look safe). So an off-curve recipient is MEDIUM (`UNKNOWN_CONTROLLER`) until an allow entry names the controller, and then that controller is judged.
- **Allowlist offers.** Offered only for an on-curve program-owned recipient (with no controller, and the question says a keypair moves the USDC), and only when the off-chain verdict is PAY. Never off the curve: the owner names the controller with `allowlistOnChain` after checking it (e.g. the address re-derives from its seeds under it).
- **Bridge.** A program-level block is written even when the recipient is already denylisted. Only states the recipient controls reach `deny`; lamports a stranger sends to a wallet's ATA address read as "missing" and can't get it denylisted, and `ensureRecipientAta` creates the ATA over them. `actOnVerdict` never throws: a failed `assess()` preview is noted, a BLOCK is recorded first, and the action names what actually happened (`recorded-block`, `blocked-no-write`, `block-not-recorded`, `pay-failed`, `pay-unknown`, ...).
- **Client.** `send()` takes the signature before sending, confirms by polling the signature status (no websocket), and treats that status as the authority on success; the transaction fetch is only for logs. `landed` is `true`, `false` (rejected by the RPC, or the blockhash expired unseen) or `null` (could not tell: check the signature before retrying).
- **Fail closed.** A HIGH fact read in round 1 survives a round-2 read failure. A guard id with no config account is UNKNOWN. With no guard id found at all, `aegisCheck` is ASK_HUMAN / LANE_UNAVAILABLE; `guard: null` opts out and the verdict says what was skipped. A large payment whose history can't be read is LANE_UNAVAILABLE, not UNUSUAL_AMOUNT. Amount 0 is rejected, as on-chain.
- **LLM.** `claude -p` also runs with `--safe-mode --strict-mcp-config --disable-slash-commands --permission-prompts none --no-session-persistence` from an empty temp directory, so no MCP servers, connectors, hooks, CLAUDE.md, skills or permission rules load. Fenced facts escape `<` and `>`. `cleanText` also strips default-ignorable code points (variation selectors). A CLI failure is reported in one short line.
- **Codes.** A failed transaction's AnchorError is attributed by following the invoke stack, so another program's error is never read as ours. The behavior lane works in base units, so "exactly 5x" is exact.
- **Not done:** Metaplex metadata for a classic mint is not read, and the look-alike check covers common Cyrillic/Greek letters and fullwidth forms, not the whole Unicode confusables table.

**Behavior lane.** It reads the stats PDA:
- missing = never paid;
- RPC error = unknown, never reported as "never".

The history is all-time, for `guarded_pay` only; x402 payments never pass the guard. The 50 USDC threshold and the 5x rule are unchanged.
Residual: any in-cap payment moves the anchor, with or without review. 50 → 250 → 1250 needs no human, and with complete history the anchor never decays. The daily cap is the hard bound.

## x402 rail (step 4)

**Fetch wrapper.** Ported with these changes:
- Addresses are compared case-sensitively.
- Network must be exactly `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`; v1 `solana-devnet` is normalized to it.
- `asset` must be the pinned USDC; otherwise `NO_PAYABLE_OPTION`, and for the demo the lane's findings on the offered mint are printed as information.
- `extra.feePayer` must be valid and must not be us.
- Amounts must fit in u64.
- `accepted` is echoed exactly as received, `extra.recentBlockhash` and `lastValidBlockHeight` included. The reference server skips those two dynamic fields when matching, so a fresh blockhash in the 402 doesn't break the match.
- The reply is `{x402Version:2, resource, accepted: <the requirement exactly as received>, payload:{transaction}, extensions: <echoed>}`.

**Signer.** A locally typed signer with kit-compatible `signTransactions` and restricted `signMessages` methods. `@solana/kit` is not installed. It re-derives everything from the message bytes and refuses unless all of these hold:

- **Message shape:** v0, no lookup tables, exactly 2 required signers, `staticAccounts[0] = feePayer ≠ us`, `staticAccounts[1] = us`.
- **Exactly these 4 instructions, pinned by program id:**
  1. CU limit (discriminator 2, ≤ 40k units);
  2. CU price (discriminator 3, capped);
  3. `TransferChecked` on `TokenkegQ…`;
  4. Memo v2.

  Nothing else, so p-token's Batch, AdvanceNonce and CreateATA are all refused.
- **`TransferChecked`:**
  - data is 10 bytes, discriminator 12, decimals 6, amount > 0;
  - exactly 4 accounts: source = ATA(us, USDC), mint = USDC, destination ≠ source, authority = us;
  - our key appears nowhere else.
- **Destination, read now from the pinned RPC:**
  - it exists, is owned by Tokenkeg, and has mint = USDC;
  - its `owner` is payTo, else `DestinationOwnerMismatch` BLOCK;
  - it is not frozen; a live delegate is judged by `aegisCheck` (HIGH/BLOCK if its allowance covers the payment, otherwise MEDIUM/ASK_HUMAN).

  The denylist runs on the actual owner. This is the on-chain `guarded_pay` check, repeated off-chain for the rail that never touches the guard.
- **Lifetime:**
  - `isBlockhashValid` is true on the pinned devnet RPC, whose genesis hash was checked at startup; otherwise `VALIDITY_WINDOW` (a genesis hash other than the configured network is `WRONG_NETWORK`);
  - durable nonce is excluded by the instruction list (`VALIDITY_WINDOW`).
- **Balance:** our USDC ATA holds ≥ amount, else `EXCEEDS_BALANCE`.
- **Simulation.** It runs on the pinned RPC with `sigVerify:false`, `replaceRecentBlockhash:false`, commitment confirmed.
  - It must return `err === null` and `unitsConsumed > 0`.
  - Token deltas, matched by (owner, mint), must be exactly {us: −amount, payTo: +amount}.
  - Both SOL balance arrays must contain one finite numeric entry per static account key; our entry at index 1 must be unchanged. Empty, short, extra or malformed arrays are `SIMULATION_MISMATCH`.
  - Any RPC error, 429 or missing field → refuse.

  The static decode is the security control. Simulation trusts our RPC, so it is a sanity and liveness check.
- **Policy:** `aegisCheck(payTo, amount)` must return PAY.
- **Memo:** see decision 6 in `MIGRATION.md`.
- **Raw signing:** `signMessages` is denied unless the message starts with `\xffsolana offchain`.

**Scope.** As on EVM, the catalog, the posted price and the per-payment cap live in the wrapper. A caller holding only the signer gets the signer's list and not the wrapper's. The rail is binding only when the key is held behind this signer. With a hosted wallet, or an Agent Kit plugin whose kit still signs with its own wallet, it is advisory.

**Audit logger.** Ported: synchronous `onRefuse`; dedupe by error-object identity; a failed write is recorded, never thrown; 25 receipts per run, which now bounds the agent's SOL; off when not configured.

**Merchant.** It acts as its own facilitator: fee payer = merchant. Settlement is tested on the local validator; no devnet settlement is claimed. It verifies with web3.js's decoder, independently of the signer's, and follows the reference facilitator's checks and error codes. `@x402/svm` is not installed, so the reference verify is not run against our transactions; interop with x402.org remains open.

**Step 4 status (2026-10-03):** built and tested; the six findings from an adversarial review are fixed. Unit tests (`tests/unit/x402-*`) run on fake chains; `tests/x402.ts` runs the rail end to end on the local validator. Deltas from the plan above:
- **Lifetime codes.** A genesis hash on the pinned RPC other than the configured network is `WRONG_NETWORK` (checked once, remembered; a failed read is retried). A blockhash that isn't current on that RPC is `VALIDITY_WINDOW`. A durable nonce can't get through, because the instruction list has no room for AdvanceNonce.
- **Destination.** The payee is the destination's owner as read from the chain, not the one the 402 named. A destination that isn't its owner's ATA is `DESTINATION_OWNER_MISMATCH`; a frozen or delegated destination is judged by `aegisCheck`, which gets the destination. Token-2022 is `WRONG_ASSET`.
- **Signer codes.** `MALFORMED_TRANSACTION`, `FEE_PAYER_IS_US` (checked first), `UNEXPECTED_INSTRUCTION`, `WRONG_ASSET`, `BAD_AMOUNT`, `BAD_DESTINATION`, `BAD_MEMO`, `WRONG_NETWORK`, `VALIDITY_WINDOW`, `DESTINATION_OWNER_MISMATCH`, `EXCEEDS_BALANCE`, `SIMULATION_MISMATCH`, `LANE_UNAVAILABLE` (an RPC read or the policy check failed: ASK_HUMAN), `DISABLED_PRIMITIVE` (raw `signMessages`), and otherwise the policy verdict's own code. Every refusal goes to `onRefuse`.
- **Wrapper.** Only the `authorization` payment flow is paid, and `assetTransferMethod` must be `default` (or absent). An empty `extra.memo` counts as none, as in the reference client. Refusal order: `NO_PAYABLE_OPTION`, then the catalog (`UNKNOWN_SERVICE`), then `OVER_POSTED_PRICE`, then human approval over the per-payment cap (`APPROVER_FAILED`, `NO_APPROVER`, `HUMAN_DECLINED`), then the signer. v1 servers (`X-PAYMENT`) are still paid.
- **Catalog origin (later audit fix).** Each payee has one canonical HTTP origin; duplicate payees are rejected. Both the URL the agent requested and the final 402 response URL must have that origin; a mismatch is `UNKNOWN_SERVICE`. A paid retry does not follow redirects, so its signature header stays at that origin. The catalog does not distinguish paths within one origin. This adds two unit cases; the owner reviewed the change and reported all 325 tests passing.
- **Merchant compute limit (later audit fix).** `verifyPayment` uses the signer's `MAX_COMPUTE_UNITS` and refuses a limit above 40,000 with the existing `INVALID.CU_LIMIT` code. The existing price cap of 5,000,000 micro-lamports per unit therefore bounds the requested priority fee to 200,000 lamports, plus the base fee. There is no separate total-fee rule or per-client rate limit. A unit test covers 1,400,000 refused and 40,000 accepted.
- **SOL evidence (later audit fix).** The signer checks both arrays against the exact static-key count before comparing our SOL balance. Each entry must be a finite number, including index 1; sparse entries also fail. Unit tests cover empty, short, extra, missing and non-numeric evidence as `SIMULATION_MISMATCH`.
- **Merchant answers like the reference v2 server.** It reads only `PAYMENT-SIGNATURE` (v2 only). `accepted` matches when every core field is deep-equal (key order ignored, types count) and `extra` holds the wanted keys, the two dynamic ones skipped; otherwise 402 with `error: "No matching payment requirements"`. An unreadable header is a plain 402. A failed check is 402 with `PAYMENT-REQUIRED` carrying the `invalid_exact_svm_*` code. A payment that verified but didn't settle (duplicate, pending, failed) is 402 with `PAYMENT-RESPONSE` `success:false`, `errorReason` and the transaction if one was broadcast. Deliberate differences: the body repeats the header instead of `{}`; when the chain can't be read it answers 503 rather than blaming the payment; and a replay is caught (sha256 of the message bytes, 120 s) before any chain check, so an already-landed payment reads `duplicate_settlement`, not a simulation failure. A send the RPC rejects, or a blockhash that expires unseen, frees the hash for a retry; a landed or unknown one keeps it.
- **Tests.** Two unit tests that built a "look-alike" by lowercasing a random key were flaky (sometimes the key had no letters to change); they now swap in a character that isn't base58. The live test covers: the float topped up only through `guarded_pay` (the x402 wallet holds 0 SOL); a real settlement with exact balance moves, the merchant paying the fee and us signing second; a replay that moves nothing; `OVER_POSTED_PRICE`, `UNKNOWN_SERVICE`, `NO_PAYABLE_OPTION` on a look-alike mint (with `NOT_PINNED_ASSET` and `FREEZE_AUTHORITY`) and `DENYLISTED` from the signer with no payment sent; and the four refusals read back from the on-chain audit log.
- **Open:** the devnet interop run against x402.org and a facilitator other than our own merchant are not done.

## Demo (step 5)

1. **Good recipient.** `guarded_pay` to a wallet's USDC ATA, with an Explorer link.
2. **Bad recipient: delegated account.** The villain's USDC account has an attacker delegate, which could sweep what we pay.
   - `assess` → REVIEW, and the lane reports it as MEDIUM or HIGH.
   - The bridge writes `deny` → `assess` becomes BLOCK. A second run reports "already blocked".
   - The check only sees a delegate set before the payment.
3. **Bad mint.** The x402 merchant offers only a Token-2022 look-alike ("USD Coin", permanent delegate, freeze authority).
   - The wrapper refuses it as `NO_PAYABLE_OPTION`, and the lane prints what the mint could do to a holder.
   - `initialize` refusing such a mint is shown in the tests, since a live devnet config already exists.
4. **Injected drain.** The agent skips Aegis and calls `guarded_pay` straight at the villain with `skipPreflight`. The transaction fails on-chain and the vault doesn't move.
5. **Kill switch.** Revoke the agent, show the same clean payment refused with `NotAgent`, then restore. The restore is confirmed by re-reading the agent PDA, and the script exits non-zero if it didn't take.

**Step 5 status (2026-10-03):** built as exported functions in `src/demo/`, an idempotent setup routine, and thin `yarn demo` / `yarn demo:setup` CLIs. `tests/demo.ts` exercises all five beats after `aegis_guard.ts`, using fresh villain keys and restoring the agent. The beat functions return verdicts, codes, signatures, balances and facts; `formatDemo` alone writes the short story and Explorer links.
- **Deltas:** `all` uses one process per beat, keeping the owner key out of the drain and x402 agent runs. The kill-switch refusal uses `skipPreflight` so its `NotAgent` failure has an Explorer link. The delegated beat says the guard checks the delegate during `guarded_pay`, and a delegate added after payment remains a risk.
- **Setup allowance (later audit fix):** setup requires 3 USDC of remaining daily allowance before adding entries or funding demo accounts. This preserves the original reserve: the default good payment and an empty float consume at most 2 USDC. It reads the Clock sysvar and uses the guard config's spend, matching `check_cap`'s floor division and forward-only day rollover; yesterday's spend resets, while an equal or earlier day retains spend. Unit tests cover today's exhausted allowance, yesterday's rollover, backward and negative time, and an unreadable Clock. Other agents can still consume the allowance after setup reads it.
- **Audit-fix verification:** findings 2–4 add eight unit cases. Typecheck passed and the unit run had 262 passing cases; the six existing HTTP merchant cases failed to bind `127.0.0.1` (`listen EPERM`) before their assertions. The files then defined 333 TypeScript cases (268 unit, 65 live); the full validator suite was not rerun here.
- **Real on localnet:** guarded USDC transfers, a delegate with maximum allowance, a Token-2022 look-alike with metadata, permanent delegate and freeze authority, an HTTP 402, an x402 refusal receipt, and failed on-chain drain and kill-switch transactions. The local USDC mint and faucet SOL are validator fixtures; reputation is still a mock, and the LLM is skipped.
- **Devnet:** scripts are cluster-aware, but no devnet deployment, funding, minting or demo run was performed here. The owner must fund SOL and Circle devnet USDC and run the sequence. The x402.org interop check and a facilitator other than our own merchant remain open.
- **Verification:** The owner reported the complete local-validator suite passing: 323 TypeScript tests (258 unit, 65 live). In the editing sandbox, typecheck and 252 socket-free unit tests passed; six HTTP merchant tests could not bind `127.0.0.1` (`listen EPERM`), and `yarn test` stopped before the validator suite because port 8899 was reported in use.

## Step 6 status (2026-10-03)

Added a short root `README.md` with the two enforcement points, test counts, real versus mock claims, security limits and local quick start. The EVM README was used for its plain treatment of limits, not copied. This documentation pass also corrected stale kit, signer-method, reference-verifier and devnet-settlement claims in `MIGRATION.md` and the step-4 design text. Typecheck passed; the sandbox ran 252 unit cases and could not bind a socket for six HTTP cases. `yarn lint` reports 47 pre-existing TypeScript formatting issues, with no mass reformat. No devnet run, new package, program change or key change was made. A root `LICENSE` was added on 2026-10-15: all rights reserved, no license granted (`package.json` says `UNLICENSED`).

**Post-step audit fixes:** A paid x402 retry now keeps an untouched request body when the first fetch consumes a `Request` or streamed body. `ensureRecipientAta` decodes an existing classic token account and refuses a wrong mint, reassigned owner, frozen state or malformed layout instead of treating it as ready. The drain formatter reports the measured before and after vault balances, including an unexpected move. The merchant still prepares `product` before settlement; its callback must only prepare response data in memory because external side effects there could happen without payment. The kill-switch beat and a separate `yarn demo:restore-agent` command use the same restoration check; the command can repair a revoked entry after a process crash or RPC outage without passing setup's funding and allowance checks.

The files define 343 TypeScript cases (278 unit, 65 live). Typecheck and the 272 unit cases that need no HTTP listener pass here. Six merchant HTTP cases cannot bind `127.0.0.1` in this sandbox, and the full validator command stops before the suite because port 8899 is reported in use. The owner has not yet rerun the full suite with these fixes.

**Devnet run (2026-10-15):** `aegis_guard` is deployed on devnet at `CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6` (upgrade authority: the deployer key; about 1.79 SOL in program rent). The vault holds Circle devnet USDC moved in by hand from the owner. `yarn demo:setup` and `yarn demo all` both completed on the public devnet RPC: all five beats gave their expected result. The public RPC throttled requests (HTTP 429) and the client retried, so use a dedicated RPC on demo day. The first deploy attempt with `--use-rpc` failed on rate limits; its buffer was closed and the SOL recovered, and the TPU deploy that followed succeeded. Not run on devnet: a successful x402 settlement, an x402.org check, a third-party facilitator.

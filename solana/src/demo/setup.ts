import {
  ExtensionType,
  TOKEN_2022_PROGRAM_ID,
  approve,
  createInitializeMetadataPointerInstruction,
  createInitializeMintInstruction,
  createInitializePermanentDelegateInstruction,
  getAccount,
  getMetadataPointerState,
  getMint,
  getMintLen,
  getPermanentDelegate,
  getTokenMetadata,
  mintTo,
  tokenMetadataInitializeWithRentTransfer,
} from "@solana/spl-token";
import { BN } from "@anchor-lang/core";
import {
  Connection,
  Keypair,
  PublicKey,
  SYSVAR_CLOCK_PUBKEY,
  SystemProgram,
} from "@solana/web3.js";

import {
  BPF_LOADER_UPGRADEABLE,
  SYSVAR_OWNER,
  TOKEN_PROGRAM,
  USDC_MINT,
} from "../config";
import { GuardClient } from "../guard/client";
import { ConfigData, associatedTokenAddress } from "../guard/layout";
import { formatUnits } from "../units";

const U64_MAX = (1n << 64n) - 1n;
const METADATA_URI = "https://example.invalid/usdc.json";
const SECONDS_PER_DAY = 86_400n;
// The good payment and an empty float use 2 USDC; keep 1 USDC in reserve.
const MIN_DEMO_ALLOWANCE = 3_000_000n;

export interface DemoSetupKeys {
  deployer?: Keypair;
  owner: Keypair;
  agent: Keypair;
  payer: Keypair;
  reporter: Keypair;
  good: Keypair;
  villain: Keypair;
  attacker: Keypair;
  float: Keypair;
  merchant: Keypair;
  badMint: Keypair;
  /** Local validator only. Never load this key for devnet. */
  mintAuthority?: Keypair;
}

export interface SetupAction {
  label: string;
  state: "done" | "skipped";
  signature?: string;
}

export interface SetupResult {
  ready: boolean;
  actions: SetupAction[];
  needed: string[];
  vault: PublicKey;
}

/** Uses the chain clock and the guard's spend, with the same rollover as check_cap. */
export async function checkDemoAllowance(
  connection: Connection,
  cfg: Pick<ConfigData, "dailyLimit" | "currentDay" | "spentToday">
): Promise<bigint> {
  const clock = await connection.getAccountInfo(
    SYSVAR_CLOCK_PUBKEY,
    "confirmed"
  );
  if (!clock?.owner.equals(SYSVAR_OWNER) || clock.data.length !== 40)
    throw new Error(
      "the chain clock could not be read; setup cannot check the remaining daily allowance"
    );
  // Clock's final field is unix_timestamp, a signed i64 at byte 32.
  const now = clock.data.readBigInt64LE(32);
  // Rust div_euclid floors negative times too. Only a later day clears spend.
  const day = now / SECONDS_PER_DAY - (now % SECONDS_PER_DAY < 0n ? 1n : 0n);
  const spent = day > cfg.currentDay ? 0n : cfg.spentToday;
  const remaining = cfg.dailyLimit - spent;
  if (remaining < MIN_DEMO_ALLOWANCE)
    throw new Error(
      `the guard has only ${formatUnits(
        remaining > 0n ? remaining : 0n
      )} USDC of remaining daily allowance; the demo needs at least ${formatUnits(
        MIN_DEMO_ALLOWANCE
      )} USDC`
    );
  return remaining;
}

/** Reads before every write, so rerunning setup only fills what is missing. */
export async function ensureDemoSetup(
  connection: Connection,
  keys: DemoSetupKeys,
  opts: {
    programId: PublicKey;
    localnet: boolean;
    vaultTarget?: bigint;
    dailyLimit?: bigint;
  }
): Promise<SetupResult> {
  const client = new GuardClient(
    connection,
    opts.programId,
    keys.agent.publicKey
  );
  const target = opts.vaultTarget ?? 20_000_000n;
  const actions: SetupAction[] = [];
  const needed: string[] = [];
  const done = (label: string, signature: string) =>
    actions.push({ label, state: "done", signature });
  const skip = (label: string) => actions.push({ label, state: "skipped" });
  const mustLand = (
    label: string,
    out: { ok: boolean; signature: string | null; error: string | null }
  ) => {
    if (!out.ok || !out.signature)
      throw new Error(`${label} did not land: ${out.error}`);
    done(label, out.signature);
  };

  const mintInfo = await connection.getAccountInfo(USDC_MINT, "confirmed");
  if (!mintInfo?.owner.equals(TOKEN_PROGRAM))
    throw new Error(
      "the classic devnet-USDC mint is absent here; start a local validator with Anchor.toml's test mint or use Solana devnet"
    );
  let cfg = await client.config();
  if (!cfg) {
    const deployer = keys.deployer;
    if (!deployer)
      throw new Error(
        "the guard has no config; the deployer key is needed to initialize it"
      );
    const programData = PublicKey.findProgramAddressSync(
      [opts.programId.toBuffer()],
      BPF_LOADER_UPGRADEABLE
    )[0];
    const ix = await client.program.methods
      .initialize(
        keys.owner.publicKey,
        new BN((opts.dailyLimit ?? 100_000_000n).toString())
      )
      .accountsPartial({
        deployer: deployer.publicKey,
        program: opts.programId,
        programData,
        config: client.pdas.config,
        audit: client.pdas.audit,
        mint: USDC_MINT,
        vault: client.pdas.vault(USDC_MINT),
      })
      .instruction();
    mustLand("initialize guard", await client.send([ix], [deployer], false));
    cfg = await client.config();
  } else skip("guard already initialized");
  if (!cfg)
    throw new Error("the guard config could not be read after initialization");
  if (!cfg.owner.equals(keys.owner.publicKey) || !cfg.mint.equals(USDC_MINT))
    throw new Error(
      "the guard's owner or mint differs from the demo keys; no setup writes were made after reading it"
    );
  if (cfg.paused)
    throw new Error(
      "the guard is paused; the owner must unpause it before the demo"
    );
  await checkDemoAllowance(connection, cfg);

  for (const [kind, key] of [
    ["agent", keys.agent.publicKey],
    ["reporter", keys.reporter.publicKey],
  ] as const) {
    if ((await client.entry(kind, key)).member)
      skip(`${kind} entry already present`);
    else
      mustLand(
        `add ${kind} entry`,
        await client.addEntry(keys.owner, kind, key)
      );
  }

  const vaultBalance = (await getAccount(connection, cfg.vault)).amount;
  if (vaultBalance < target) {
    const amount = target - vaultBalance;
    if (!opts.localnet) {
      needed.push(
        `Vault ${cfg.vault.toBase58()} needs ${formatUnits(
          amount
        )} USDC. Fund it from faucet.circle.com or transfer devnet USDC into this vault, then rerun setup. Devnet setup never mints.`
      );
      return { ready: false, actions, needed, vault: cfg.vault };
    }
    if (!keys.mintAuthority)
      throw new Error(
        "the localnet mint authority fixture is needed to fund the test vault"
      );
    done(
      `mint ${formatUnits(amount)} localnet test USDC to vault`,
      await mintTo(
        connection,
        keys.payer,
        USDC_MINT,
        cfg.vault,
        keys.mintAuthority,
        amount
      )
    );
  } else skip(`vault already holds at least ${formatUnits(target)} USDC`);

  for (const [label, recipient] of [
    ["good", keys.good.publicKey],
    ["villain", keys.villain.publicKey],
    ["float", keys.float.publicKey],
  ] as const) {
    const made = await client.ensureRecipientAta(keys.payer, recipient);
    if (made.created && made.outcome?.signature)
      done(`create ${label} USDC account`, made.outcome.signature);
    else skip(`${label} USDC account already present`);
  }

  const villainAta = associatedTokenAddress(keys.villain.publicKey, USDC_MINT);
  const villainAccount = await getAccount(connection, villainAta);
  if (!villainAccount.owner.equals(keys.villain.publicKey))
    throw new Error(
      "the villain's USDC account was reassigned; setup cannot give it a safe demonstration delegate"
    );
  if (
    villainAccount.delegate?.equals(keys.attacker.publicKey) &&
    villainAccount.delegatedAmount === U64_MAX
  )
    skip("villain delegate already set");
  else
    done(
      "approve attacker as villain's USDC delegate",
      await approve(
        connection,
        keys.payer,
        villainAta,
        keys.attacker.publicKey,
        keys.villain,
        U64_MAX
      )
    );

  const badMintInfo = await connection.getAccountInfo(
    keys.badMint.publicKey,
    "confirmed"
  );
  if (!badMintInfo) {
    const mintLen = getMintLen([
      ExtensionType.PermanentDelegate,
      ExtensionType.MetadataPointer,
    ]);
    const lamports = await connection.getMinimumBalanceForRentExemption(
      mintLen
    );
    const ix = [
      SystemProgram.createAccount({
        fromPubkey: keys.payer.publicKey,
        newAccountPubkey: keys.badMint.publicKey,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      createInitializePermanentDelegateInstruction(
        keys.badMint.publicKey,
        keys.attacker.publicKey,
        TOKEN_2022_PROGRAM_ID
      ),
      createInitializeMetadataPointerInstruction(
        keys.badMint.publicKey,
        keys.payer.publicKey,
        keys.badMint.publicKey,
        TOKEN_2022_PROGRAM_ID
      ),
      createInitializeMintInstruction(
        keys.badMint.publicKey,
        6,
        keys.payer.publicKey,
        keys.payer.publicKey,
        TOKEN_2022_PROGRAM_ID
      ),
    ];
    mustLand(
      "create Token-2022 look-alike mint",
      await client.send(ix, [keys.payer, keys.badMint], false)
    );
  } else skip("look-alike mint already present");
  const badMint = await getMint(
    connection,
    keys.badMint.publicKey,
    "confirmed",
    TOKEN_2022_PROGRAM_ID
  );
  if (
    !badMint.freezeAuthority?.equals(keys.payer.publicKey) ||
    !getPermanentDelegate(badMint)?.delegate.equals(keys.attacker.publicKey) ||
    !getMetadataPointerState(badMint)?.metadataAddress?.equals(
      keys.badMint.publicKey
    )
  ) {
    throw new Error(
      "the existing look-alike mint lacks the expected freeze authority, permanent delegate or metadata pointer"
    );
  }
  const metadata = await getTokenMetadata(
    connection,
    keys.badMint.publicKey,
    "confirmed",
    TOKEN_2022_PROGRAM_ID
  );
  if (!metadata) {
    done(
      "write USD Coin / USDC look-alike metadata",
      await tokenMetadataInitializeWithRentTransfer(
        connection,
        keys.payer,
        keys.badMint.publicKey,
        keys.payer.publicKey,
        keys.payer,
        "USD Coin",
        "USDC",
        METADATA_URI,
        [],
        undefined,
        TOKEN_2022_PROGRAM_ID
      )
    );
  } else if (metadata.name === "USD Coin" && metadata.symbol === "USDC")
    skip("look-alike metadata already present");
  else throw new Error("the existing look-alike mint has different metadata");

  return { ready: true, actions, needed, vault: cfg.vault };
}

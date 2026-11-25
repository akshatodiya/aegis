use anchor_lang::prelude::*;

#[constant]
pub const CONFIG_SEED: &[u8] = b"config";
#[constant]
pub const AUDIT_SEED: &[u8] = b"audit";
#[constant]
pub const PAID_SEED: &[u8] = b"paid";
#[constant]
pub const AGENT_SEED: &[u8] = b"agent";
#[constant]
pub const DENY_SEED: &[u8] = b"deny";
#[constant]
pub const ALLOW_SEED: &[u8] = b"allow";
#[constant]
pub const BLOCKPROG_SEED: &[u8] = b"blockprog";
#[constant]
pub const REPORTER_SEED: &[u8] = b"reporter";

pub const MAX_REASON_LEN: usize = 256;
pub const MAX_CODE_LEN: usize = 32;
pub const SECONDS_PER_DAY: i64 = 86_400;

/// Tokens sent here are burned for good.
pub const INCINERATOR: Pubkey = pubkey!("1nc1nerator11111111111111111111111111111111");
/// Owner of every sysvar account.
pub const SYSVAR_OWNER: Pubkey = pubkey!("Sysvar1111111111111111111111111111111111111");
pub const TOKEN_2022_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Accounts owned by a loader are programs, ProgramData or buffers. Tokens sent
/// to one are stranded.
pub const LOADERS: [Pubkey; 5] = [
    pubkey!("BPFLoaderUpgradeab1e11111111111111111111111"),
    pubkey!("BPFLoader2111111111111111111111111111111111"),
    pubkey!("BPFLoader1111111111111111111111111111111111"),
    pubkey!("LoaderV411111111111111111111111111111111111"),
    pubkey!("NativeLoader1111111111111111111111111111111"),
];

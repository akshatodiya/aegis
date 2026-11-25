use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::AegisError;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub owner: Pubkey,
    pub pending_owner: Option<Pubkey>,
    pub mint: Pubkey,
    pub vault: Pubkey,
    /// Base units per UTC day. 0 means frozen: nothing pays.
    pub daily_limit: u64,
    pub current_day: i64,
    pub spent_today: u64,
    pub paused: bool,
    pub pay_count: u64,
    pub bump: u8,
}

/// Kept apart from Config so refusals don't write-lock `guarded_pay`.
#[account]
#[derive(InitSpace)]
pub struct AuditLog {
    pub total_refusals: u64,
    pub bump: u8,
}

/// One per list member. The account existing (owned by this program, with this
/// discriminator, at the canonical PDA) is the membership.
#[account]
#[derive(InitSpace)]
pub struct Entry {
    /// Allow entries only: the program that signs for a PDA recipient, so a
    /// later block on that program still wins. Default key when not applicable.
    pub controller: Pubkey,
    pub bump: u8,
}

/// Per-recipient payment history, written only by `guarded_pay`.
#[account]
#[derive(InitSpace)]
pub struct Stats {
    pub count: u64,
    pub largest: u64,
    pub total: u64,
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    Agent,
    Deny,
    Allow,
    BlockProgram,
    Reporter,
}

impl EntryKind {
    pub fn seed(&self) -> &'static [u8] {
        match self {
            EntryKind::Agent => AGENT_SEED,
            EntryKind::Deny => DENY_SEED,
            EntryKind::Allow => ALLOW_SEED,
            EntryKind::BlockProgram => BLOCKPROG_SEED,
            EntryKind::Reporter => REPORTER_SEED,
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Pay,
    Review,
    Block,
}

/// What `log_refusal` accepts. Borsh rejects any other byte, so a PAY can't be
/// recorded.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefusalVerdict {
    Block,
    AskHuman,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    Clear,
    Paused,
    BadAmount,
    SinkRecipient,
    Denylisted,
    ProgramRecipient,
    TokenAccountRecipient,
    SysvarRecipient,
    BlockedProgram,
    UnvettedProgramRecipient,
    BadDestination,
    DestinationOwnerMismatch,
    FrozenDestination,
    DelegatedDestination,
    DailyCap,
}

impl Reason {
    pub fn verdict(&self) -> Verdict {
        match self {
            Reason::Clear => Verdict::Pay,
            Reason::Paused
            | Reason::UnvettedProgramRecipient
            | Reason::DelegatedDestination
            | Reason::DailyCap => Verdict::Review,
            _ => Verdict::Block,
        }
    }

    pub fn error(&self) -> AegisError {
        match self {
            // never raised: Clear pays
            Reason::Clear => AegisError::MathOverflow,
            Reason::Paused => AegisError::Paused,
            Reason::BadAmount => AegisError::BadAmount,
            Reason::SinkRecipient => AegisError::SinkRecipient,
            Reason::Denylisted => AegisError::Denylisted,
            Reason::ProgramRecipient => AegisError::ProgramRecipient,
            Reason::TokenAccountRecipient => AegisError::TokenAccountRecipient,
            Reason::SysvarRecipient => AegisError::SysvarRecipient,
            Reason::BlockedProgram => AegisError::BlockedProgram,
            Reason::UnvettedProgramRecipient => AegisError::UnvettedProgramRecipient,
            Reason::BadDestination => AegisError::BadDestination,
            Reason::DestinationOwnerMismatch => AegisError::DestinationOwnerMismatch,
            Reason::FrozenDestination => AegisError::FrozenDestination,
            Reason::DelegatedDestination => AegisError::DelegatedDestination,
            Reason::DailyCap => AegisError::DailyCap,
        }
    }
}

/// Returned by `assess` as an Ok value, never as an error.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Assessment {
    pub verdict: Verdict,
    pub reason: Reason,
    pub day: i64,
    pub spent_today: u64,
    pub daily_limit: u64,
}

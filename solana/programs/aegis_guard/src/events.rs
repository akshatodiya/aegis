use anchor_lang::prelude::*;

use crate::state::{EntryKind, RefusalVerdict};

#[event]
pub struct Paid {
    pub id: u64,
    pub agent: Pubkey,
    pub recipient: Pubkey,
    pub destination: Pubkey,
    pub amount: u64,
    pub day: i64,
    pub spent_today: u64,
}

#[event]
pub struct Refused {
    pub id: u64,
    pub reporter: Pubkey,
    pub recipient: Option<Pubkey>,
    pub amount: u64,
    pub verdict: RefusalVerdict,
    pub code: String,
    pub reason: String,
    pub timestamp: i64,
}

#[event]
pub struct EntrySet {
    pub kind: EntryKind,
    pub key: Pubkey,
    pub on: bool,
    pub controller: Pubkey,
}

#[event]
pub struct DailyLimitSet {
    pub limit: u64,
}

#[event]
pub struct PausedSet {
    pub paused: bool,
}

#[event]
pub struct OwnershipTransferStarted {
    pub from: Pubkey,
    pub to: Option<Pubkey>,
}

#[event]
pub struct OwnershipTransferred {
    pub from: Pubkey,
    pub to: Pubkey,
}

#[event]
pub struct Withdrawn {
    pub to: Pubkey,
    pub amount: u64,
}

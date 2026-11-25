pub mod constants;
pub mod error;
pub mod events;
pub mod instructions;
pub mod policy;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
pub use instructions::*;
pub use state::*;

declare_id!("CTvcbeF4MziHgc1BsiAQY9fZkub9hYFS8CJ336V1QJG6");

#[program]
pub mod aegis_guard {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, owner: Pubkey, daily_limit: u64) -> Result<()> {
        crate::instructions::initialize::handle_initialize(ctx, owner, daily_limit)
    }

    pub fn add_entry(
        ctx: Context<AddEntry>,
        kind: EntryKind,
        key: Pubkey,
        controller: Pubkey,
    ) -> Result<()> {
        crate::instructions::entries::handle_add_entry(ctx, kind, key, controller)
    }

    pub fn remove_entry(ctx: Context<RemoveEntry>, kind: EntryKind, key: Pubkey) -> Result<()> {
        crate::instructions::entries::handle_remove_entry(ctx, kind, key)
    }

    pub fn set_daily_limit(ctx: Context<OwnerOnly>, limit: u64) -> Result<()> {
        crate::instructions::admin::handle_set_daily_limit(ctx, limit)
    }

    pub fn set_paused(ctx: Context<OwnerOnly>, paused: bool) -> Result<()> {
        crate::instructions::admin::handle_set_paused(ctx, paused)
    }

    pub fn transfer_ownership(ctx: Context<OwnerOnly>, next: Option<Pubkey>) -> Result<()> {
        crate::instructions::admin::handle_transfer_ownership(ctx, next)
    }

    pub fn accept_ownership(ctx: Context<AcceptOwnership>) -> Result<()> {
        crate::instructions::admin::handle_accept_ownership(ctx)
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        crate::instructions::admin::handle_withdraw(ctx, amount)
    }

    pub fn guarded_pay(ctx: Context<GuardedPay>, amount: u64) -> Result<()> {
        crate::instructions::guarded_pay::handle_guarded_pay(ctx, amount)
    }

    pub fn assess(ctx: Context<Assess>, amount: u64) -> Result<Assessment> {
        crate::instructions::assess::handle_assess(ctx, amount)
    }

    pub fn log_refusal(
        ctx: Context<LogRefusal>,
        recipient: Option<Pubkey>,
        amount: u64,
        verdict: RefusalVerdict,
        code: String,
        reason: String,
    ) -> Result<()> {
        crate::instructions::log_refusal::handle_log_refusal(
            ctx, recipient, amount, verdict, code, reason,
        )
    }
}

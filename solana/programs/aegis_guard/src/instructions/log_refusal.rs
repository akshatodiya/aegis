use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::AegisError;
use crate::events::Refused;
use crate::policy::is_member;
use crate::state::{AuditLog, Config, RefusalVerdict};

#[event_cpi]
#[derive(Accounts)]
pub struct LogRefusal<'info> {
    pub reporter: Signer<'info>,
    /// CHECK: membership is judged in the handler.
    #[account(seeds = [REPORTER_SEED, config.key().as_ref(), reporter.key().as_ref()], bump)]
    pub reporter_entry: UncheckedAccount<'info>,
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [AUDIT_SEED, config.key().as_ref()], bump = audit.bump)]
    pub audit: Account<'info, AuditLog>,
}

/// A receipt for an off-chain refusal. It touches no vault account.
pub fn handle_log_refusal(
    ctx: Context<LogRefusal>,
    recipient: Option<Pubkey>,
    amount: u64,
    verdict: RefusalVerdict,
    code: String,
    reason: String,
) -> Result<()> {
    require!(
        is_member(&ctx.accounts.reporter_entry, ctx.program_id),
        AegisError::NotReporter
    );
    require!(
        !reason.is_empty() && reason.len() <= MAX_REASON_LEN,
        AegisError::BadReason
    );
    require!(
        !code.is_empty()
            && code.len() <= MAX_CODE_LEN
            && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
        AegisError::BadCode
    );

    let audit = &mut ctx.accounts.audit;
    let id = audit
        .total_refusals
        .checked_add(1)
        .ok_or(AegisError::MathOverflow)?;
    audit.total_refusals = id;

    emit_cpi!(Refused {
        id,
        reporter: ctx.accounts.reporter.key(),
        recipient,
        amount,
        verdict,
        code,
        reason,
        timestamp: Clock::get()?.unix_timestamp,
    });
    Ok(())
}

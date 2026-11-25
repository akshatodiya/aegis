use anchor_lang::prelude::*;

use crate::constants::*;
use crate::policy::{evaluate, PolicyAccounts};
use crate::state::{Assessment, Config, Reason, Verdict};

// All read-only, so the client can call it with `.view()`.
#[derive(Accounts)]
pub struct Assess<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: any account; classified by `evaluate()`.
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: parsed and checked by `evaluate()`.
    pub destination: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; membership judged by `evaluate()`.
    #[account(seeds = [DENY_SEED, config.key().as_ref(), recipient.key().as_ref()], bump)]
    pub deny_entry: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; membership judged by `evaluate()`.
    #[account(seeds = [ALLOW_SEED, config.key().as_ref(), recipient.key().as_ref()], bump)]
    pub allow_entry: UncheckedAccount<'info>,
    /// CHECK: address checked by `evaluate()`.
    pub blockprog_owner: UncheckedAccount<'info>,
    /// CHECK: address checked by `evaluate()` when needed.
    pub blockprog_controller: Option<UncheckedAccount<'info>>,
}

/// Same `evaluate()` as `guarded_pay`, without the agent check. The day
/// rollover is computed but not written.
pub fn handle_assess(ctx: Context<Assess>, amount: u64) -> Result<Assessment> {
    let now = Clock::get()?.unix_timestamp;
    let accts = &ctx.accounts;
    let config = &accts.config;
    let verdict = evaluate(
        ctx.program_id,
        &config.key(),
        config,
        &PolicyAccounts {
            recipient: accts.recipient.as_ref(),
            destination: accts.destination.as_ref(),
            deny_entry: accts.deny_entry.as_ref(),
            allow_entry: accts.allow_entry.as_ref(),
            blockprog_owner: accts.blockprog_owner.as_ref(),
            blockprog_controller: accts.blockprog_controller.as_ref().map(|a| a.as_ref()),
        },
        amount,
        now,
    )?;
    let day = now.div_euclid(SECONDS_PER_DAY).max(config.current_day);
    let spent_today = if day > config.current_day {
        0
    } else {
        config.spent_today
    };
    let reason = match verdict {
        Ok(_) => Reason::Clear,
        Err(reason) => reason,
    };
    Ok(Assessment {
        verdict: if reason == Reason::Clear {
            Verdict::Pay
        } else {
            reason.verdict()
        },
        reason,
        day,
        spent_today,
        daily_limit: config.daily_limit,
    })
}

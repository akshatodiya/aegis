use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, TransferChecked};

use crate::constants::*;
use crate::error::AegisError;
use crate::events::Paid;
use crate::policy::{evaluate, is_member, PolicyAccounts};
use crate::state::{Config, Stats};

// The struct only pins addresses. Everything policy reads is unchecked here and
// judged in `evaluate()`, so refusals come back as typed Aegis errors in a fixed
// order instead of framework constraint errors.
#[event_cpi]
#[derive(Accounts)]
pub struct GuardedPay<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,
    /// CHECK: membership is judged in the handler.
    #[account(seeds = [AGENT_SEED, config.key().as_ref(), agent.key().as_ref()], bump)]
    pub agent_entry: UncheckedAccount<'info>,

    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(mut, address = config.vault)]
    pub vault: Box<Account<'info, TokenAccount>>,
    #[account(address = config.mint)]
    pub mint: Box<Account<'info, Mint>>,

    /// CHECK: any account; classified by `evaluate()`.
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: parsed and checked by `evaluate()`.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; membership judged by `evaluate()`.
    #[account(seeds = [DENY_SEED, config.key().as_ref(), recipient.key().as_ref()], bump)]
    pub deny_entry: UncheckedAccount<'info>,
    /// CHECK: canonical PDA; membership judged by `evaluate()`.
    #[account(seeds = [ALLOW_SEED, config.key().as_ref(), recipient.key().as_ref()], bump)]
    pub allow_entry: UncheckedAccount<'info>,
    /// CHECK: blockprog PDA for the recipient's owner; address checked by `evaluate()`.
    pub blockprog_owner: UncheckedAccount<'info>,
    /// CHECK: blockprog PDA for the allow entry's controller, when it has one.
    pub blockprog_controller: Option<UncheckedAccount<'info>>,

    #[account(
        init_if_needed,
        payer = agent,
        space = 8 + Stats::INIT_SPACE,
        seeds = [PAID_SEED, config.key().as_ref(), recipient.key().as_ref()],
        bump,
    )]
    pub stats: Box<Account<'info, Stats>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

pub fn handle_guarded_pay(ctx: Context<GuardedPay>, amount: u64) -> Result<()> {
    // First, so a revoked agent is refused before any policy runs.
    require!(
        is_member(&ctx.accounts.agent_entry, ctx.program_id),
        AegisError::NotAgent
    );

    let now = Clock::get()?.unix_timestamp;
    let accts = &ctx.accounts;
    let blockprog_controller = accts.blockprog_controller.as_ref().map(|a| a.as_ref());
    let verdict = evaluate(
        ctx.program_id,
        &accts.config.key(),
        &accts.config,
        &PolicyAccounts {
            recipient: accts.recipient.as_ref(),
            destination: accts.destination.as_ref(),
            deny_entry: accts.deny_entry.as_ref(),
            allow_entry: accts.allow_entry.as_ref(),
            blockprog_owner: accts.blockprog_owner.as_ref(),
            blockprog_controller,
        },
        amount,
        now,
    )?;
    let cleared = match verdict {
        Ok(c) => c,
        Err(reason) => {
            msg!("aegis: {:?} ({:?})", reason.verdict(), reason);
            return Err(reason.error().into());
        }
    };

    // Book the spend before the transfer.
    let config = &mut ctx.accounts.config;
    config.current_day = cleared.day;
    config.spent_today = cleared.spent_today;
    config.pay_count = config
        .pay_count
        .checked_add(1)
        .ok_or(AegisError::MathOverflow)?;
    let id = config.pay_count;
    let bump = config.bump;

    let signer: &[&[&[u8]]] = &[&[CONFIG_SEED, &[bump]]];
    token::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
        )
        .with_signer(signer),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    let stats = &mut ctx.accounts.stats;
    stats.count = stats.count.checked_add(1).ok_or(AegisError::MathOverflow)?;
    stats.total = stats
        .total
        .checked_add(amount)
        .ok_or(AegisError::MathOverflow)?;
    stats.largest = stats.largest.max(amount);
    stats.bump = ctx.bumps.stats;

    emit_cpi!(Paid {
        id,
        agent: ctx.accounts.agent.key(),
        recipient: ctx.accounts.recipient.key(),
        destination: ctx.accounts.destination.key(),
        amount,
        day: cleared.day,
        spent_today: cleared.spent_today,
    });
    Ok(())
}

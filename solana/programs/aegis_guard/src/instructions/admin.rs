use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, TransferChecked};

use crate::constants::*;
use crate::error::AegisError;
use crate::events::*;
use crate::state::Config;

#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ AegisError::NotOwner,
    )]
    pub config: Account<'info, Config>,
}

pub fn handle_set_daily_limit(ctx: Context<OwnerOnly>, limit: u64) -> Result<()> {
    ctx.accounts.config.daily_limit = limit;
    emit!(DailyLimitSet { limit });
    Ok(())
}

pub fn handle_set_paused(ctx: Context<OwnerOnly>, paused: bool) -> Result<()> {
    ctx.accounts.config.paused = paused;
    emit!(PausedSet { paused });
    Ok(())
}

/// Step one of two. `None` cancels a pending transfer.
pub fn handle_transfer_ownership(ctx: Context<OwnerOnly>, next: Option<Pubkey>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.pending_owner = next;
    emit!(OwnershipTransferStarted {
        from: config.owner,
        to: next,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct AcceptOwnership<'info> {
    pub new_owner: Signer<'info>,
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        constraint = config.pending_owner == Some(new_owner.key()) @ AegisError::NotPendingOwner,
    )]
    pub config: Account<'info, Config>,
}

pub fn handle_accept_ownership(ctx: Context<AcceptOwnership>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    let to = ctx.accounts.new_owner.key();
    emit!(OwnershipTransferred {
        from: config.owner,
        to,
    });
    config.owner = to;
    config.pending_owner = None;
    Ok(())
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub owner: Signer<'info>,
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ AegisError::NotOwner,
    )]
    pub config: Account<'info, Config>,
    #[account(mut, address = config.vault)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = config.mint)]
    pub mint: Account<'info, Mint>,
    #[account(mut, token::mint = mint)]
    pub to: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

/// Uncapped, and works while paused: the owner is effectively the treasury key.
pub fn handle_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(amount > 0, AegisError::BadAmount);
    let bump = ctx.accounts.config.bump;
    let signer: &[&[&[u8]]] = &[&[CONFIG_SEED, &[bump]]];
    token::transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.to.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
        )
        .with_signer(signer),
        amount,
        ctx.accounts.mint.decimals,
    )?;
    emit!(Withdrawn {
        to: ctx.accounts.to.key(),
        amount,
    });
    Ok(())
}

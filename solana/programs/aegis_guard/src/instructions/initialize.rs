use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::*;
use crate::error::AegisError;
use crate::events::DailyLimitSet;
use crate::program::AegisGuard;
use crate::state::{AuditLog, Config};

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub deployer: Signer<'info>,

    // Only the upgrade authority may initialize, which closes the front-run on
    // the global config PDA.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ AegisError::NotUpgradeAuthority)]
    pub program: Program<'info, AegisGuard>,
    #[account(constraint = program_data.upgrade_authority_address == Some(deployer.key()) @ AegisError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,

    #[account(
        init,
        payer = deployer,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump,
    )]
    pub config: Account<'info, Config>,

    #[account(
        init,
        payer = deployer,
        space = 8 + AuditLog::INIT_SPACE,
        seeds = [AUDIT_SEED, config.key().as_ref()],
        bump,
    )]
    pub audit: Account<'info, AuditLog>,

    /// Classic Token only: `Account<Mint>` refuses a Token-2022 mint by owner.
    pub mint: Account<'info, Mint>,

    // init_if_needed: anyone can create the config PDA's ATA ahead of us. An ATA
    // made by the ATA program can't carry a delegate the PDA didn't sign for,
    // but the handler checks anyway.
    #[account(
        init_if_needed,
        payer = deployer,
        associated_token::mint = mint,
        associated_token::authority = config,
        associated_token::token_program = token_program,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

pub fn handle_initialize(ctx: Context<Initialize>, owner: Pubkey, daily_limit: u64) -> Result<()> {
    let vault = &ctx.accounts.vault;
    require!(
        vault.owner == ctx.accounts.config.key()
            && vault.delegate.is_none()
            && vault.close_authority.is_none(),
        AegisError::BadVault
    );

    let config = &mut ctx.accounts.config;
    config.owner = owner;
    config.pending_owner = None;
    config.mint = ctx.accounts.mint.key();
    config.vault = vault.key();
    config.daily_limit = daily_limit;
    config.current_day = Clock::get()?.unix_timestamp.div_euclid(SECONDS_PER_DAY);
    config.spent_today = 0;
    config.paused = false;
    config.pay_count = 0;
    config.bump = ctx.bumps.config;

    let audit = &mut ctx.accounts.audit;
    audit.total_refusals = 0;
    audit.bump = ctx.bumps.audit;

    emit!(DailyLimitSet { limit: daily_limit });
    Ok(())
}

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::error::AegisError;
use crate::events::EntrySet;
use crate::state::{Config, Entry, EntryKind};

#[derive(Accounts)]
#[instruction(kind: EntryKind, key: Pubkey)]
pub struct AddEntry<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ AegisError::NotOwner,
    )]
    pub config: Account<'info, Config>,
    // init_if_needed: idempotent like the EVM setters, and works on an address
    // someone pre-funded with lamports.
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + Entry::INIT_SPACE,
        seeds = [kind.seed(), config.key().as_ref(), key.as_ref()],
        bump,
    )]
    pub entry: Account<'info, Entry>,
    pub system_program: Program<'info, System>,
}

/// `controller` is kept for Allow entries only (the program that signs for a
/// PDA recipient); pass the default key when there is none.
pub fn handle_add_entry(
    ctx: Context<AddEntry>,
    kind: EntryKind,
    key: Pubkey,
    controller: Pubkey,
) -> Result<()> {
    let controller = if kind == EntryKind::Allow {
        controller
    } else {
        Pubkey::default()
    };
    let entry = &mut ctx.accounts.entry;
    entry.controller = controller;
    entry.bump = ctx.bumps.entry;
    emit!(EntrySet {
        kind,
        key,
        on: true,
        controller,
    });
    Ok(())
}

#[derive(Accounts)]
#[instruction(kind: EntryKind, key: Pubkey)]
pub struct RemoveEntry<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = owner @ AegisError::NotOwner,
    )]
    pub config: Account<'info, Config>,
    #[account(
        mut,
        close = owner,
        seeds = [kind.seed(), config.key().as_ref(), key.as_ref()],
        bump = entry.bump,
    )]
    pub entry: Account<'info, Entry>,
}

pub fn handle_remove_entry(_ctx: Context<RemoveEntry>, kind: EntryKind, key: Pubkey) -> Result<()> {
    emit!(EntrySet {
        kind,
        key,
        on: false,
        controller: Pubkey::default(),
    });
    Ok(())
}

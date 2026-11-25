//! `evaluate()`: the one policy both `guarded_pay` and `assess` run.
//!
//! Order matters and is pinned by tests: sinks, then deny before allow, then
//! the recipient's kind, then program control, then the destination token
//! account, then the cap. The agent check is not in here; `guarded_pay` runs
//! it first, and `assess` takes no agent (as on EVM).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use anchor_spl::token;

use crate::constants::*;
use crate::error::AegisError;
use crate::state::{Config, Entry, Reason};

/// Classic Token account layout (165 bytes).
const TOKEN_ACCOUNT_LEN: usize = 165;
const TA_STATE_UNINITIALIZED: u8 = 0;
const TA_STATE_FROZEN: u8 = 2;

pub struct Cleared {
    pub day: i64,
    pub spent_today: u64,
}

pub struct PolicyAccounts<'a, 'info> {
    pub recipient: &'a AccountInfo<'info>,
    pub destination: &'a AccountInfo<'info>,
    pub deny_entry: &'a AccountInfo<'info>,
    pub allow_entry: &'a AccountInfo<'info>,
    pub blockprog_owner: &'a AccountInfo<'info>,
    pub blockprog_controller: Option<&'a AccountInfo<'info>>,
}

/// Outer `Err` is a malformed call (wrong entry address). Inner `Err` is a
/// policy verdict other than PAY.
pub fn evaluate(
    program_id: &Pubkey,
    config_key: &Pubkey,
    config: &Config,
    accts: &PolicyAccounts,
    amount: u64,
    now: i64,
) -> Result<std::result::Result<Cleared, Reason>> {
    if config.paused {
        return Ok(Err(Reason::Paused));
    }
    if amount == 0 {
        return Ok(Err(Reason::BadAmount));
    }

    let recipient = accts.recipient.key;
    let owner = accts.recipient.owner;

    // Config and the audit log are owned by this program, so the owner check
    // covers them.
    if *recipient == Pubkey::default()
        || *recipient == INCINERATOR
        || recipient == config_key
        || *recipient == config.vault
        || owner == program_id
    {
        return Ok(Err(Reason::SinkRecipient));
    }

    if is_member(accts.deny_entry, program_id) {
        return Ok(Err(Reason::Denylisted));
    }

    // Classify by data owner. Never by `executable` or by the curve alone.
    if LOADERS.contains(owner) {
        return Ok(Err(Reason::ProgramRecipient));
    }
    if *owner == token::ID || *owner == TOKEN_2022_ID {
        return Ok(Err(Reason::TokenAccountRecipient));
    }
    if *owner == SYSVAR_OWNER {
        return Ok(Err(Reason::SysvarRecipient));
    }

    // Always checked, so the caller can't point it somewhere empty.
    require_entry_address(
        accts.blockprog_owner,
        BLOCKPROG_SEED,
        config_key,
        owner,
        program_id,
    )?;

    let system_owned = *owner == system_program::ID;
    if !system_owned || !recipient.is_on_curve() {
        if !system_owned && is_member(accts.blockprog_owner, program_id) {
            return Ok(Err(Reason::BlockedProgram));
        }
        match read_entry(accts.allow_entry, program_id) {
            Some(allow) => {
                // A data-less PDA reads as System-owned, so a block on the
                // program that signs for it has to be looked up by controller.
                if allow.controller != Pubkey::default() {
                    let acct = accts
                        .blockprog_controller
                        .ok_or(AegisError::MissingControllerEntry)?;
                    require_entry_address(
                        acct,
                        BLOCKPROG_SEED,
                        config_key,
                        &allow.controller,
                        program_id,
                    )?;
                    if is_member(acct, program_id) {
                        return Ok(Err(Reason::BlockedProgram));
                    }
                }
            }
            None => return Ok(Err(Reason::UnvettedProgramRecipient)),
        }
    }

    if let Err(reason) = check_destination(accts.destination, recipient, &config.mint) {
        return Ok(Err(reason));
    }

    Ok(check_cap(
        config.daily_limit,
        config.current_day,
        config.spent_today,
        amount,
        now,
    ))
}

fn check_destination(
    destination: &AccountInfo,
    recipient: &Pubkey,
    mint: &Pubkey,
) -> std::result::Result<(), Reason> {
    if *destination.owner != token::ID || destination.data_len() != TOKEN_ACCOUNT_LEN {
        return Err(Reason::BadDestination);
    }
    let data = destination
        .try_borrow_data()
        .map_err(|_| Reason::BadDestination)?;
    let state = data[108];
    if state == TA_STATE_UNINITIALIZED || data[0..32] != mint.as_ref()[..] {
        return Err(Reason::BadDestination);
    }
    // Classic Token lets an ATA's owner be reassigned, so the address alone
    // proves nothing.
    if data[32..64] != recipient.as_ref()[..] {
        return Err(Reason::DestinationOwnerMismatch);
    }
    if state == TA_STATE_FROZEN {
        return Err(Reason::FrozenDestination);
    }
    let has_delegate = u32::from_le_bytes(data[72..76].try_into().unwrap()) == 1;
    let delegated_amount = u64::from_le_bytes(data[121..129].try_into().unwrap());
    if has_delegate && delegated_amount > 0 {
        return Err(Reason::DelegatedDestination);
    }
    Ok(())
}

/// Pure so the day rollover can be unit-tested; the test validator can't move
/// its clock.
pub fn check_cap(
    daily_limit: u64,
    current_day: i64,
    spent_today: u64,
    amount: u64,
    now: i64,
) -> std::result::Result<Cleared, Reason> {
    let day = now.div_euclid(SECONDS_PER_DAY);
    // Only roll forward. If the clock ever reads an earlier day, keep today's
    // spend rather than reset it.
    let (day, spent) = if day > current_day {
        (day, 0)
    } else {
        (current_day, spent_today)
    };
    if daily_limit == 0 {
        return Err(Reason::DailyCap);
    }
    match spent.checked_add(amount) {
        Some(total) if total <= daily_limit => Ok(Cleared {
            day,
            spent_today: total,
        }),
        _ => Err(Reason::DailyCap),
    }
}

/// Anyone can send lamports to any address, so an account only counts when this
/// program owns it and it carries the Entry discriminator.
pub fn is_member(acct: &AccountInfo, program_id: &Pubkey) -> bool {
    if acct.owner != program_id {
        return false;
    }
    match acct.try_borrow_data() {
        Ok(data) => data.starts_with(Entry::DISCRIMINATOR),
        Err(_) => false,
    }
}

fn read_entry(acct: &AccountInfo, program_id: &Pubkey) -> Option<Entry> {
    if !is_member(acct, program_id) {
        return None;
    }
    let data = acct.try_borrow_data().ok()?;
    Entry::try_deserialize(&mut &data[..]).ok()
}

/// The canonical-bump PDA only. A non-canonical bump could point at an empty
/// address and "prove" non-membership.
fn require_entry_address(
    acct: &AccountInfo,
    seed: &[u8],
    config_key: &Pubkey,
    key: &Pubkey,
    program_id: &Pubkey,
) -> Result<()> {
    let (expected, _) =
        Pubkey::find_program_address(&[seed, config_key.as_ref(), key.as_ref()], program_id);
    require_keys_eq!(*acct.key, expected, AegisError::BadEntryAccount);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = SECONDS_PER_DAY;

    #[test]
    fn same_day_accumulates() {
        let c = check_cap(100, 5, 40, 60, 5 * DAY + 10).ok().unwrap();
        assert_eq!((c.day, c.spent_today), (5, 100));
        assert_eq!(
            check_cap(100, 5, 40, 61, 5 * DAY + 10).err(),
            Some(Reason::DailyCap)
        );
    }

    #[test]
    fn next_day_resets() {
        let c = check_cap(100, 5, 100, 100, 6 * DAY).ok().unwrap();
        assert_eq!((c.day, c.spent_today), (6, 100));
    }

    #[test]
    fn skipped_days_reset() {
        let c = check_cap(100, 5, 100, 1, 9 * DAY + 3).ok().unwrap();
        assert_eq!((c.day, c.spent_today), (9, 1));
    }

    #[test]
    fn midnight_burst_is_twice_the_limit() {
        // Known limitation of fixed UTC buckets, same as EVM.
        let a = check_cap(100, 5, 0, 100, 6 * DAY - 1).ok().unwrap();
        assert_eq!(a.spent_today, 100);
        let b = check_cap(100, a.day, a.spent_today, 100, 6 * DAY)
            .ok()
            .unwrap();
        assert_eq!((b.day, b.spent_today), (6, 100));
    }

    #[test]
    fn zero_limit_freezes() {
        assert_eq!(check_cap(0, 5, 0, 1, 5 * DAY).err(), Some(Reason::DailyCap));
    }

    #[test]
    fn overflow_is_refused() {
        assert_eq!(
            check_cap(u64::MAX, 5, u64::MAX, 1, 5 * DAY).err(),
            Some(Reason::DailyCap)
        );
    }

    #[test]
    fn clock_going_back_keeps_spend() {
        assert_eq!(
            check_cap(100, 6, 100, 1, 5 * DAY).err(),
            Some(Reason::DailyCap)
        );
    }

    #[test]
    fn negative_time_rounds_down() {
        let c = check_cap(100, -2, 0, 1, -1).ok().unwrap();
        assert_eq!(c.day, -1);
    }
}

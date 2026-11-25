use anchor_lang::prelude::*;

// The first block mirrors `Reason` one to one, so a refused `guarded_pay`
// carries the same name that `assess` returns.
#[error_code]
pub enum AegisError {
    #[msg("signer is not an agent")]
    NotAgent,
    #[msg("guard is paused")]
    Paused,
    #[msg("amount must be greater than zero")]
    BadAmount,
    #[msg("recipient is a sink: default key, incinerator, or an Aegis account")]
    SinkRecipient,
    #[msg("recipient is denylisted")]
    Denylisted,
    #[msg("recipient is a program, ProgramData or buffer")]
    ProgramRecipient,
    #[msg("recipient is a mint, token account or multisig")]
    TokenAccountRecipient,
    #[msg("recipient is a sysvar")]
    SysvarRecipient,
    #[msg("recipient's program is blocked")]
    BlockedProgram,
    #[msg("program-controlled recipient is not vetted")]
    UnvettedProgramRecipient,
    #[msg("destination is not an initialized token account for the guarded mint")]
    BadDestination,
    #[msg("destination token account is not owned by the recipient")]
    DestinationOwnerMismatch,
    #[msg("destination token account is frozen")]
    FrozenDestination,
    #[msg("destination token account has a live delegate")]
    DelegatedDestination,
    #[msg("over the daily limit")]
    DailyCap,

    #[msg("signer is not the owner")]
    NotOwner,
    #[msg("signer is not the pending owner")]
    NotPendingOwner,
    #[msg("signer is not the program's upgrade authority")]
    NotUpgradeAuthority,
    #[msg("signer is not a reporter")]
    NotReporter,
    #[msg("entry account is not at its canonical address")]
    BadEntryAccount,
    #[msg("allow entry names a controller, so its blockprog account is required")]
    MissingControllerEntry,
    #[msg("reason must be 1 to 256 bytes")]
    BadReason,
    #[msg("code must be 1 to 32 characters of A-Z and _")]
    BadCode,
    #[msg("vault has a delegate, a close authority or the wrong owner")]
    BadVault,
    #[msg("arithmetic overflow")]
    MathOverflow,
}

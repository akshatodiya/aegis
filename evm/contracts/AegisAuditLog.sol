// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title AegisAuditLog
/// @notice An on-chain record of the payments Aegis REFUSED on the x402 rail.
/// @dev This is a receipt, not a gate. It sits outside every payment path and
///      nothing in it can stop anything. Read on before wiring it up.
///
///      Why it exists: on the treasury rail a refusal is already on-chain. The
///      agent calls guardedPay, the policy fails, the transaction reverts, and
///      the reverted tx is the receipt - anyone can open it on the explorer. The
///      x402 rail has no such artifact. There a payment is an EIP-3009 signature
///      that a facilitator settles later, so a refusal is the *absence* of a
///      signature: nothing is broadcast, nothing is mined, and the only evidence
///      the firewall did anything is a line of console output on the machine that
///      refused. This contract is where that line goes so an outsider can read it.
///
///      What an entry is worth, stated plainly:
///        - It proves a reporter said it refused a payment. It does not prove a
///          payment was ever demanded, and it cannot prove one was stopped - by
///          the time this is called the signature was already never created.
///        - Silence proves nothing. A compromised agent simply does not call
///          this, so an empty log is not evidence that nothing was refused.
///        - Only reporters the owner authorized can write, so a stranger cannot
///          mint entries that look like ours. That bounds forgery by outsiders,
///          not dishonesty by the reporter: the log is exactly as truthful as the
///          key that writes it.
///
///      Deliberately a separate contract: AegisGuard is verified on Arc testnet
///      and adding to it would mean redeploying the thing under the receipts.
contract AegisAuditLog {
    /// @dev Only the two refusing verdicts exist here, which is what keeps this a
    ///      refusal log by construction rather than by convention: the ABI
    ///      decoder reverts on any other value, so a PAY cannot be recorded, and
    ///      the cost of the whole thing stays bounded by how rare refusals are.
    ///      Mirrors the off-chain engine's BLOCK and ASK_HUMAN.
    enum Verdict { Block, AskHuman }

    address public owner;
    address public pendingOwner;

    // who may write. the agent's hot key goes in here; the owner key stays out
    // of the loop, exactly like isAgent on the guard.
    mapping(address => bool) public isReporter;

    // the one piece of state worth paying for. an eth_getLogs query is capped by
    // whatever the RPC gateway feels like returning over whatever block window
    // the caller asked for, so a reader that finds four entries cannot tell a
    // complete log from a truncated one. this is the number to check against.
    uint256 public totalRefusals;

    // reasons come from the wire (a hostile 402 can put its own digits inside
    // "demanding N base units"), so the length is attacker-influenced and gets a
    // hard ceiling here rather than an assumption that the caller trimmed it.
    uint256 public constant MAX_REASON_BYTES = 256;

    /// @param reasonHash keccak256 of `reason`, indexed so a reader can filter by
    ///        an exact reason without scanning; `reason` itself is in the data.
    /// @param id the entry's 1-based position, so a reader that fetched entries
    ///        1, 2 and 5 knows precisely which ones its query missed rather than
    ///        only that the count came up short. (Three topics are already spent
    ///        on the fields worth filtering by, so this rides in the data.)
    event Refused(
        address indexed reporter,
        address indexed recipient,
        bytes32 indexed reasonHash,
        uint256 id,
        Verdict verdict,
        uint256 amount,
        string reason
    );
    event ReporterSet(address indexed reporter, bool allowed);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error NotReporter();
    error EmptyReason();
    error ReasonTooLong(uint256 length, uint256 max);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ---- admin, owner only ----

    function setReporter(address who, bool allowed) external onlyOwner {
        isReporter[who] = allowed;
        emit ReporterSet(who, allowed);
    }

    // two-step, same as the guard: a fat-fingered address never becomes owner.
    function transferOwnership(address next) external onlyOwner {
        pendingOwner = next;
        emit OwnershipTransferStarted(owner, next);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // ---- the log ----

    /// @notice Record that Aegis refused to pay `recipient`.
    /// @param recipient who we declined to pay. May be the zero address: some
    ///        refusals happen before the 402 has named a payable recipient, and
    ///        zero says "we never got that far" rather than inventing one.
    /// @param amount the demanded amount in USDC base units (6 decimals).
    /// @param verdict Block or AskHuman.
    /// @param reason the human-readable reason, same string the agent printed.
    /// @return id the entry's 1-based position in the log.
    function logRefusal(
        address recipient,
        uint256 amount,
        Verdict verdict,
        string calldata reason
    ) external returns (uint256 id) {
        if (!isReporter[msg.sender]) revert NotReporter();

        bytes calldata raw = bytes(reason);
        // an entry with no reason is worse than no entry - it looks like a
        // record while carrying nothing anyone could check.
        if (raw.length == 0) revert EmptyReason();
        if (raw.length > MAX_REASON_BYTES) revert ReasonTooLong(raw.length, MAX_REASON_BYTES);

        unchecked { id = ++totalRefusals; } // one per refusal; it will not wrap
        emit Refused(msg.sender, recipient, keccak256(raw), id, verdict, amount, reason);
    }
}

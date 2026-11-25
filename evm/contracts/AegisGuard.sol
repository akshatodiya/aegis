// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title AegisGuard
/// @notice On-chain payment firewall for AI agents spending USDC.
/// @dev The money lives in `treasury`, which grants an ERC20 allowance ONLY to
///      this contract. Agents are whitelisted to *trigger* payments through
///      guardedPay but never hold the funds, so a leaked agent key cannot move
///      money outside the policy enforced here. assess() is reused inside
///      guardedPay, so the check and the transfer are one atomic call - there is
///      no gap for the recipient to change code between them (no TOCTOU).
contract AegisGuard {
    // same three verdicts as the off-chain checker
    enum Verdict { Pay, Block, Review }

    address public owner;
    address public pendingOwner;
    address public immutable token; // the USDC we guard
    address public treasury;        // holds the funds, approves this contract

    // agents allowed to trigger a payment
    mapping(address => bool) public isAgent;

    // reputation lane, real on-chain lists now
    mapping(address => bool) public denylisted;
    mapping(address => bool) public allowedContract; // code recipients must be vetted; plain EOAs pass

    // bytecode lane. a kill-switch for a whole bytecode family in one write:
    // block by keccak256(runtime code) so N identical deployments die at once.
    mapping(bytes32 => bool) public blockedCodehash;

    // behavior lane. rolling per-day spend cap in token base units (0 = off).
    // this is real state, not a static per-tx check, so splitting a payment
    // into chunks still hits the same daily wall.
    // TODO: per-agent limits once there's more than one agent in play.
    uint256 public dailyLimit;
    mapping(uint256 => uint256) public spentOnDay; // day index -> amount spent that day

    event Paid(address indexed agent, address indexed to, uint256 amount);
    event AgentSet(address indexed agent, bool allowed);
    event Denylisted(address indexed who, bool bad);
    event ContractAllowed(address indexed who, bool ok);
    event CodehashBlocked(bytes32 indexed codehash, bool bad);
    event DailyLimitSet(uint256 limit);
    event TreasurySet(address indexed treasury);
    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error NotAgent();
    error ZeroAddress();
    error Denied(Verdict verdict, string reason);
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address usdc, address treasury_, uint256 dailyLimit_) {
        if (usdc == address(0) || treasury_ == address(0)) revert ZeroAddress();
        owner = msg.sender;
        token = usdc;
        treasury = treasury_;
        dailyLimit = dailyLimit_;
        emit TreasurySet(treasury_);
        emit DailyLimitSet(dailyLimit_);
    }

    // ---- policy, owner only ----
    // in practice the off-chain analyzer (opcode scan + llm) is what calls these
    // once it decides something is bad. kept deliberately boring.

    function setAgent(address who, bool allowed) external onlyOwner {
        isAgent[who] = allowed;
        emit AgentSet(who, allowed);
    }

    function setDenylisted(address who, bool bad) external onlyOwner {
        denylisted[who] = bad;
        emit Denylisted(who, bad);
    }

    function setAllowedContract(address who, bool ok) external onlyOwner {
        allowedContract[who] = ok;
        emit ContractAllowed(who, ok);
    }

    function setBlockedCodehash(bytes32 codehash, bool bad) external onlyOwner {
        blockedCodehash[codehash] = bad;
        emit CodehashBlocked(codehash, bad);
    }

    function setDailyLimit(uint256 limit) external onlyOwner {
        dailyLimit = limit;
        emit DailyLimitSet(limit);
    }

    function setTreasury(address t) external onlyOwner {
        if (t == address(0)) revert ZeroAddress();
        treasury = t;
        emit TreasurySet(t);
    }

    // two-step ownership so a fat-fingered address can't brick admin
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

    // ---- the firewall ----

    // day bucket for the spend accounting. fine for a per-day cap; not meant to
    // be a precise clock (miners can nudge block.timestamp a few seconds).
    function today() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    /// @notice Verdict for a payment without moving anything.
    /// @dev Reused inside guardedPay so the preview and the binding check are the
    ///      exact same code. Deny rules are checked before allow rules.
    /// @param to recipient of the payment
    /// @param amount token base units to send
    function assess(address to, uint256 amount)
        public
        view
        returns (Verdict verdict, string memory reason)
    {
        if (to == address(0)) return (Verdict.Block, "zero address");
        if (denylisted[to]) return (Verdict.Block, "recipient denylisted");

        // note: code.length > 0 does not strictly mean "contract" post-Pectra -
        // an EIP-7702 delegated EOA also carries code. treating both as
        // must-be-vetted is the conservative (safe) call.
        if (to.code.length > 0) {
            if (blockedCodehash[to.codehash]) return (Verdict.Block, "recipient code is blocklisted");
            if (!allowedContract[to]) return (Verdict.Review, "unvetted contract recipient");
        }

        if (dailyLimit != 0 && spentOnDay[today()] + amount > dailyLimit) {
            return (Verdict.Review, "over daily limit");
        }

        return (Verdict.Pay, "clear");
    }

    /// @notice Send `amount` USDC from the treasury to `to`, only if policy says Pay.
    /// @dev Caller must be a whitelisted agent. Treasury must have approved this
    ///      contract for at least `amount`. Spend is booked before the transfer
    ///      (checks-effects-interactions).
    function guardedPay(address to, uint256 amount) external returns (bool) {
        if (!isAgent[msg.sender]) revert NotAgent();

        (Verdict verdict, string memory reason) = assess(to, amount);
        if (verdict != Verdict.Pay) revert Denied(verdict, reason);

        spentOnDay[today()] += amount;
        _safeTransferFrom(treasury, to, amount);

        emit Paid(msg.sender, to, amount);
        return true;
    }

    // USDC returns a bool and reverts on failure; this also tolerates the tokens
    // that return no data at all. hand-rolled so the build stays solc-js only,
    // no OpenZeppelin import callback to wire up.
    function _safeTransferFrom(address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// HoneypotVault - a deliberately malicious payment recipient, used as the demo
// villain. this is exactly the kind of address a payment firewall is supposed
// to stop an agent from paying into.
//
// it presents on-chain as a friendly "vault" you can deposit into, but the
// bytecode carries three patterns pulled straight from real losses:
//
//   1. a swappable-logic delegatecall proxy + an unprotected selfdestruct.
//      this is the shape behind the Parity multisig freeze (Nov 2017): a
//      library was selfdestructed through the proxy and ~280M USD of ETH got
//      permanently bricked. funds you send here can be frozen or rugged.
//
//   2. an owner "sweep" reachable via tx.origin. tx.origin auth is the classic
//      phishing anti-pattern - a victim's own transaction ends up authorizing
//      the drain. the same idea powers the wallet-drainer kits (Inferno / Pink
//      Drainer) that took 300M USD+ across 2023-24.
//
// Aegis reads this contract's bytecode, sees SELFDESTRUCT + DELEGATECALL +
// tx.origin, scores it HIGH, and blocks the payment before it ever signs.

contract HoneypotVault {
    address public owner;
    address public logic; // "upgradeable" logic target, swapped by the owner

    constructor() {
        owner = msg.sender;
    }

    // looks like a normal deposit an agent might be asked to pay into
    function deposit() external payable {}

    receive() external payable {}

    // owner can point the vault at new logic. tx.origin instead of msg.sender is
    // the phishing tell: a call routed through another contract still passes.
    function upgrade(address newLogic) external {
        require(tx.origin == owner, "not owner");
        logic = newLogic;
    }

    // Parity-style kill switch. wipes the contract (and can strand balances).
    function kill() external {
        require(tx.origin == owner, "not owner");
        selfdestruct(payable(owner));
    }

    // everything else is forwarded to the swappable logic via delegatecall, so
    // the code that actually runs can be changed out from under a depositor.
    fallback() external payable {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok, "logic call failed");
    }
}

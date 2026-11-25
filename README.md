# Aegis

A firewall for AI agents that pay in USDC. Before a payment leaves, Aegis checks
**who is getting paid** and answers **PAY**, **BLOCK** or **ASK_HUMAN**.

It enforces at the last point where a payment can still be stopped, on two rails:

- **Treasury:** the agent pays through an on-chain guard, so a hijacked agent that
  skips every off-chain check still fails on-chain.
- **x402:** the agent pays a service over HTTP, so Aegis wraps the signer, and a
  payment it does not approve is never signed.

The same tool is built for two chains:

| Folder | Chain | Stack |
|---|---|---|
| [`evm/`](evm/) | Arc (Circle's stablecoin L1), also Ethereum Sepolia | Node.js, viem, Solidity |
| [`solana/`](solana/) | Solana devnet | Anchor (Rust), TypeScript |

Each folder is a separate project with its own README, setup and tests. Start there.

The browser checker for the EVM version is hosted at
[akshatodiya.github.io/aegis/evm/web/check.html](https://akshatodiya.github.io/aegis/evm/web/check.html).

Licensing differs between the two folders: see [`solana/LICENSE`](solana/LICENSE)
and [`evm/package.json`](evm/package.json).

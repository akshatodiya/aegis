#!/bin/sh
# Runs a command with the Solana release pinned in Anchor.toml first on PATH.
# `anchor` then finds that version already active and never switches the
# machine-wide `agave-install` release. Uses an installed release only.
set -e
ver=$(sed -n 's/^solana_version = "\(.*\)"/\1/p' Anchor.toml)
bin="${SOLANA_RELEASES_DIR:-$HOME/.local/share/solana/install/releases}/$ver/solana-release/bin"
if [ ! -x "$bin/solana" ]; then
  echo "Solana $ver is not installed at $bin" >&2
  exit 1
fi
PATH="$bin:$PATH" exec "$@"

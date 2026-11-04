#!/usr/bin/env bash
# TRANSPORT-23: plexus-core carries no rmcp, in any feature set, on any edge.
# The MCP protocol stack lives in plexus-transport-mcp, and in plexus-transport
# behind `mcp`. Run by tests/rmcp_boundary.rs, so it fails `cargo test`.
set -uo pipefail
cd "$(dirname "$0")/.."
cargo=${CARGO:-cargo}
status=0

for flags in "" "--no-default-features" "--all-features"; do
  label=${flags:-default}
  # shellcheck disable=SC2086
  if ! tree=$("$cargo" tree --prefix none -e normal,build,dev --target all $flags 2>&1); then
    echo "FAIL [$label]: cargo tree did not run:"
    echo "$tree"
    status=1
    continue
  fi
  found=$(echo "$tree" | sed -n 's/^rmcp v\([^ ]*\).*/\1/p' | sort -u | paste -sd, -)
  if [ -n "$found" ]; then
    echo "FAIL [$label]: rmcp $found in plexus-core's tree"
    status=1
  else
    echo "ok   [$label]: no rmcp"
  fi
done
exit $status

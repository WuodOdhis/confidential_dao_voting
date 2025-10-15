#!/usr/bin/env bash
set -euo pipefail

# Deployment script for Arbitrum
# Usage: RPC_URL=<url> PRIVATE_KEY=<key> ./deploy_arbitrum.sh

: "${RPC_URL:?RPC_URL environment variable must be set}"
: "${PRIVATE_KEY:?PRIVATE_KEY environment variable must be set}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Deploying Private Tally contracts to Arbitrum..."
echo "RPC: $RPC_URL"

cd "$ROOT/contracts"

# Deploy using Foundry script
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast \
  --verify \
  -vvv

echo "Deployment complete!"


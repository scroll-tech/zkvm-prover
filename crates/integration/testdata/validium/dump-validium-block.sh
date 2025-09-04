#!/bin/sh

if [[ -z "$SBV_CLI" ]]; then
    echo "Error: SBV_CLI is not set" >&2
    exit 1
fi
echo Using sbv cli from $SBV_CLI

RPC_URL=${RPC_URL:-"http://10.6.11.77:38545"}
echo "Using RPC URL: $RPC_URL"

if [[ -z "$1" ]]; then
    echo "Usage: $0 <block_number>" >&2
    exit 1
fi

BLOCK_NUMBER=$1
HEX_BLOCK_NUMBER=$(printf "0x%x" "$BLOCK_NUMBER")
echo "Dumping block number: $BLOCK_NUMBER ($HEX_BLOCK_NUMBER)"

"$SBV_CLI" dump --rpc "$RPC_URL" --block "$BLOCK_NUMBER"

cast rpc --rpc-url "$RPC_URL" scroll_getL1MessagesInBlock "$HEX_BLOCK_NUMBER" "synced" | jq > "${BLOCK_NUMBER}_validium_txs.json"

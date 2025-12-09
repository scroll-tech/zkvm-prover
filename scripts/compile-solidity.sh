#!/bin/bash
echo "$1 -> $2"
# version: solc-linux-amd64-v0.8.19+commit.7dd6d404
solc --bin "$1" | grep 6080 | xxd -r -p > "$2"

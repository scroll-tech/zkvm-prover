#!/bin/bash
set -xeu

# release version
SCROLL_ZKVM_VERSION=0.5.2
if [ -z "${SCROLL_ZKVM_VERSION}" ]; then
  echo "SCROLL_ZKVM_VERSION not set"
  exit 1
fi

function download_by_s3() {
  aws --profile default s3 cp s3://circuit-release/scroll-zkvm/releases/$SCROLL_ZKVM_VERSION releases/$SCROLL_ZKVM_VERSION --recursive
}

function download_by_http() {
  for f in chunk/app.vmexe \
    chunk/openvm.toml \
    verifier/openVmVk.json \
    verifier/verifier.bin \
    bundle/digest_1.hex \
    bundle/app.vmexe \
    bundle/digest_2.hex \
    bundle/openvm.toml \
    batch/app.vmexe \
    batch/openvm.toml; do
    output_path="releases/$SCROLL_ZKVM_VERSION/$f"
    mkdir -p "$(dirname "$output_path")"
    wget https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/releases/$SCROLL_ZKVM_VERSION/$f -O "$output_path"
  done
}

download_by_http $SCROLL_ZKVM_VERSION

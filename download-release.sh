#!/bin/bash

# release version
if [ -z "${SCROLL_ZKVM_VERSION}" ]; then
  echo "SCROLL_ZKVM_VERSION not set"
  exit 1
fi

mkdir -p releases

aws --profile default s3 cp s3://circuit-release/scroll-zkvm/releases/$SCROLL_ZKVM_VERSION releases/$SCROLL_ZKVM_VERSION --recursive

#!/bin/bash

# release version
if [ -z "${SCROLL_ZKVM_VERSION}" ]; then
  echo "SCROLL_ZKVM_VERSION not set"
  exit 1
fi

mkdir -p releases

aws --profile default s3 cp s3://circuit-release/scroll-zkvm/releases/$SCROLL_ZKVM_VERSION releases/$SCROLL_ZKVM_VERSION --recursive

# copy release assets to correct path in workdir, in preparation for integration tests
cp releases/$SCROLL_ZKVM_VERSION/chunk/app.vmexe crates/circuits/chunk-circuit/openvm/app.vmexe
cp releases/$SCROLL_ZKVM_VERSION/batch/app.vmexe crates/circuits/batch-circuit/openvm/app.vmexe
cp releases/$SCROLL_ZKVM_VERSION/bundle/app.vmexe crates/circuits/bundle-circuit/openvm/app.vmexe

#!/bin/bash

# release version
if [ -z "${COMMIT_REF}" ]; then
  echo "COMMIT_REF not set => get HEAD"
  COMMIT_REF=$(git rev-parse HEAD)
fi

# chunk-circuit exe
wget https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/$COMMIT_REF/chunk/app.vmexe -O crates/circuits/chunk-circuit/openvm/app.vmexe

# batch-circuit exe
wget https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/$COMMIT_REF/batch/app.vmexe -O crates/circuits/batch-circuit/openvm/app.vmexe

# bundle-circuit exe
wget https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/$COMMIT_REF/bundle/app.vmexe -O crates/circuits/bundle-circuit/openvm/app.vmexe

# root verifier
wget https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/$COMMIT_REF/root_verifier.asm -O crates/build-guest/root_verifier.asm

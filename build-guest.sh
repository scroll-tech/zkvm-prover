#!/usr/bin/env bash

# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# run docker image
docker run --platform linux/amd64 --name build-guest -e FEATURE=${FEATURE} build-guest:local

# copy commitments from container to local (prover)
docker cp build-guest:/app/crates/prover/src/commitments/chunk.rs crates/prover/src/commitments/chunk.rs
docker cp build-guest:/app/crates/prover/src/commitments/batch.rs crates/prover/src/commitments/batch.rs
docker cp build-guest:/app/crates/prover/src/commitments/bundle.rs crates/prover/src/commitments/bundle.rs
docker cp build-guest:/app/crates/prover/src/commitments/chunk_legacy.rs crates/prover/src/commitments/chunk_legacy.rs
docker cp build-guest:/app/crates/prover/src/commitments/batch_legacy.rs crates/prover/src/commitments/batch_legacy.rs
docker cp build-guest:/app/crates/prover/src/commitments/bundle_legacy.rs crates/prover/src/commitments/bundle_legacy.rs

# copy commitments to local (verifier)
cp crates/prover/src/commitments/chunk.rs crates/verifier/src/commitments/chunk.rs
cp crates/prover/src/commitments/batch.rs crates/verifier/src/commitments/batch.rs
cp crates/prover/src/commitments/bundle.rs crates/verifier/src/commitments/bundle.rs
cp crates/prover/src/commitments/chunk_legacy.rs crates/verifier/src/commitments/chunk_legacy.rs
cp crates/prover/src/commitments/batch_legacy.rs crates/verifier/src/commitments/batch_legacy.rs
cp crates/prover/src/commitments/bundle_legacy.rs crates/verifier/src/commitments/bundle_legacy.rs

# copy commitments to local (circuits)
cp crates/prover/src/commitments/chunk.rs crates/circuits/batch-circuit/src/child_commitments.rs
cp crates/prover/src/commitments/batch.rs crates/circuits/bundle-circuit/src/child_commitments.rs
cp crates/prover/src/commitments/chunk_legacy.rs crates/circuits/batch-circuit/src/child_commitments_legacy.rs
cp crates/prover/src/commitments/batch_legacy.rs crates/circuits/bundle-circuit/src/child_commitments_legacy.rs

# copy app.vmexe from container to local
mkdir -p crates/circuits/chunk-circuit/openvm
mkdir -p crates/circuits/batch-circuit/openvm
mkdir -p crates/circuits/bundle-circuit/openvm
docker cp build-guest:/app/crates/circuits/chunk-circuit/openvm/app.vmexe crates/circuits/chunk-circuit/openvm/app.vmexe
docker cp build-guest:/app/crates/circuits/batch-circuit/openvm/app.vmexe crates/circuits/batch-circuit/openvm/app.vmexe
docker cp build-guest:/app/crates/circuits/bundle-circuit/openvm/app.vmexe crates/circuits/bundle-circuit/openvm/app.vmexe

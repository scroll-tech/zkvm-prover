#!/usr/bin/env bash

# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# run docker image
docker run --cidfile ./build-guest.cid --platform linux/amd64 -e FEATURE=${FEATURE} build-guest:local
container_id=$(cat ./build-guest.cid)
rm ./build-guest.cid

# copy commitments from container to local (prover)
docker cp ${container_id}:/app/crates/prover/src/commitments/chunk.rs crates/prover/src/commitments/chunk.rs
docker cp ${container_id}:/app/crates/prover/src/commitments/chunk_rv32.rs crates/prover/src/commitments/chunk_rv32.rs
docker cp ${container_id}:/app/crates/prover/src/commitments/batch.rs crates/prover/src/commitments/batch.rs
docker cp ${container_id}:/app/crates/prover/src/commitments/bundle.rs crates/prover/src/commitments/bundle.rs
docker cp ${container_id}:/app/crates/prover/src/commitments/bundle_euclidv1.rs crates/prover/src/commitments/bundle_euclidv1.rs

# copy commitments to local (verifier)
cp crates/prover/src/commitments/chunk.rs crates/verifier/src/commitments/chunk.rs
cp crates/prover/src/commitments/chunk_rv32.rs crates/verifier/src/commitments/chunk_rv32.rs
cp crates/prover/src/commitments/batch.rs crates/verifier/src/commitments/batch.rs
cp crates/prover/src/commitments/bundle.rs crates/verifier/src/commitments/bundle.rs
cp crates/prover/src/commitments/bundle_euclidv1.rs crates/verifier/src/commitments/bundle_euclidv1.rs

# copy commitments to local (circuits)
cp crates/prover/src/commitments/chunk.rs crates/circuits/batch-circuit/src/child_commitments.rs
cp crates/prover/src/commitments/chunk_rv32.rs crates/circuits/batch-circuit/src/child_commitments_rv32.rs
cp crates/prover/src/commitments/batch.rs crates/circuits/bundle-circuit/src/child_commitments.rs

# copy root verifier
docker cp ${container_id}:/app/crates/build-guest/root_verifier.asm crates/build-guest/root_verifier.asm

# copy app.vmexe from container to local
mkdir -p crates/circuits/chunk-circuit/openvm
mkdir -p crates/circuits/batch-circuit/openvm
mkdir -p crates/circuits/bundle-circuit/openvm
docker cp ${container_id}:/app/crates/circuits/chunk-circuit/openvm/app.vmexe crates/circuits/chunk-circuit/openvm/app.vmexe
docker cp ${container_id}:/app/crates/circuits/chunk-circuit/openvm/app_rv32.vmexe crates/circuits/chunk-circuit/openvm/app_rv32.vmexe
docker cp ${container_id}:/app/crates/circuits/batch-circuit/openvm/app.vmexe crates/circuits/batch-circuit/openvm/app.vmexe
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/openvm/app.vmexe crates/circuits/bundle-circuit/openvm/app.vmexe
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/openvm/app_euclidv1.vmexe crates/circuits/bundle-circuit/openvm/app_euclidv1.vmexe

# copy digests from container to local
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_1 crates/circuits/bundle-circuit/digest_1
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_2 crates/circuits/bundle-circuit/digest_2
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_1_euclidv1 crates/circuits/bundle-circuit/digest_1_euclidv1
docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_2_euclidv1 crates/circuits/bundle-circuit/digest_2_euclidv1

# remove docker container
docker rm ${container_id}

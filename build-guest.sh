#!/usr/bin/env bash

# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# run docker image
docker run --cidfile ./build-guest.cid --platform linux/amd64 -e FEATURE=${FEATURE} build-guest:local
container_id=$(cat ./build-guest.cid)
rm ./build-guest.cid

# copy commitments from container to local
for f in chunk-circuit/chunk_exe_commit.rs \
         chunk-circuit/chunk_exe_rv32_commit.rs \
         chunk-circuit/chunk_leaf_commit.rs \
         batch-circuit/batch_exe_commit.rs \
         batch-circuit/batch_leaf_commit.rs \
         bundle-circuit/bundle_exe_commit.rs \
         bundle-circuit/bundle_euclidv1_commit.rs \
         bundle-circuit/bundle_leaf_commit.rs; do
    docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
done

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

#!/usr/bin/env bash
set -ex

[ -f "crates/build-guest/.env" ] && . crates/build-guest/.env

# if BUILD_STAGES if empty, set it to stage1,stage2,stage3
if [ -z "${BUILD_STAGES}" ]; then
  BUILD_STAGES="stage1,stage2,stage3"
fi

# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# run docker image
docker run --cidfile ./build-guest.cid --platform linux/amd64 -e FEATURE=${FEATURE} build-guest:local
container_id=$(cat ./build-guest.cid)

if [ -n "$(echo ${BUILD_STAGES} | grep stage1)" ]; then
  # copy leaf commitments from container to local
  for f in chunk-circuit/chunk_leaf_commit.rs \
    batch-circuit/batch_leaf_commit.rs \
    bundle-circuit/bundle_leaf_commit.rs; do
    docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
  done
  docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_2 crates/circuits/bundle-circuit/digest_2
fi

if [ -n "$(echo ${BUILD_STAGES} | grep stage2)" ]; then
  # copy root verifier
  docker cp ${container_id}:/app/crates/build-guest/root_verifier.asm crates/build-guest/root_verifier.asm
fi

if [ -n "$(echo ${BUILD_STAGES} | grep stage3)" ]; then
  # copy exe commitments from container to local
  for f in chunk-circuit/chunk_exe_commit.rs \
    chunk-circuit/chunk_exe_rv32_commit.rs \
    batch-circuit/batch_exe_commit.rs \
    bundle-circuit/bundle_exe_commit.rs \
    bundle-circuit/bundle_exe_euclidv1_commit.rs; do
    docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
  done

  # copy digests from container to local
  docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_1 crates/circuits/bundle-circuit/digest_1
  docker cp ${container_id}:/app/crates/circuits/bundle-circuit/digest_1_euclidv1 crates/circuits/bundle-circuit/digest_1_euclidv1

  # copy app.vmexe from container to local
  mkdir -p crates/circuits/chunk-circuit/openvm
  mkdir -p crates/circuits/batch-circuit/openvm
  mkdir -p crates/circuits/bundle-circuit/openvm
  docker cp ${container_id}:/app/crates/circuits/chunk-circuit/openvm/app.vmexe crates/circuits/chunk-circuit/openvm/app.vmexe
  docker cp ${container_id}:/app/crates/circuits/chunk-circuit/openvm/app_rv32.vmexe crates/circuits/chunk-circuit/openvm/app_rv32.vmexe
  docker cp ${container_id}:/app/crates/circuits/batch-circuit/openvm/app.vmexe crates/circuits/batch-circuit/openvm/app.vmexe
  docker cp ${container_id}:/app/crates/circuits/bundle-circuit/openvm/app.vmexe crates/circuits/bundle-circuit/openvm/app.vmexe
  docker cp ${container_id}:/app/crates/circuits/bundle-circuit/openvm/app_euclidv1.vmexe crates/circuits/bundle-circuit/openvm/app_euclidv1.vmexe

fi

# remove docker container
docker rm ${container_id}
rm ./build-guest.cid

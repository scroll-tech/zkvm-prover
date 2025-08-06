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
fi

if [ -n "$(echo ${BUILD_STAGES} | grep stage2)" ]; then
  # copy root verifier
  docker cp ${container_id}:/app/crates/build-guest/root_verifier.asm crates/build-guest/root_verifier.asm
fi

if [ -n "$(echo ${BUILD_STAGES} | grep stage3)" ]; then
  # copy exe commitments from container to local
  for f in chunk-circuit/chunk_exe_commit.rs \
    batch-circuit/batch_exe_commit.rs \
    bundle-circuit/bundle_exe_commit.rs; do
    docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
  done

  # copy release files from container to local
  docker cp -r ${container_id}:/app/releases/dev releases/dev

fi

# remove docker container
docker rm ${container_id}
rm ./build-guest.cid

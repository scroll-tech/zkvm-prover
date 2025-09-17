#!/usr/bin/env bash
set -ex

mkdir -p releases
#rm -rf releases/*

# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# cleanup function
cleanup() {

  if [ -f ./build-guest.cid ]; then
    docker rm -f $(cat ./build-guest.cid) 2>/dev/null || true
  fi
  rm -f ./build-guest.cid

}

# set trap to cleanup on exit
trap cleanup EXIT

# run docker image
docker run --cidfile ./build-guest.cid --platform linux/amd64 build-guest:local make build-guest-local
container_id=$(cat ./build-guest.cid)

# copy vm commitments from container to local
for f in chunk-circuit/chunk_vm_commit.rs \
  batch-circuit/batch_vm_commit.rs \
  bundle-circuit/bundle_vm_commit.rs; do
  docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
done

# copy root verifier
docker cp ${container_id}:/app/crates/build-guest/root_verifier.asm crates/build-guest/root_verifier.asm

# copy exe commitments from container to local
for f in chunk-circuit/chunk_exe_commit.rs \
  batch-circuit/batch_exe_commit.rs \
  bundle-circuit/bundle_exe_commit.rs; do
  docker cp ${container_id}:/app/crates/circuits/${f} crates/circuits/${f}
done

# copy release files from container to local
docker cp ${container_id}:/app/releases/dev/. releases/dev/

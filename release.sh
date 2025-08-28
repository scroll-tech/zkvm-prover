#!/bin/bash
set -uex

if [ -z "${SCROLL_ZKVM_VERSION}" ]; then
  echo "SCROLL_ZKVM_VERSION not set"
  exit 1
else
  VERIFIER_RELEASES_DIR="releases/${SCROLL_ZKVM_VERSION}"
fi

DEV_DIR="releases/dev"
# Output sha256 checksums
find $DEV_DIR -type f ! -name sha256sums.txt -exec sha256sum {} \; >$DEV_DIR/sha256sums.txt

# Read FORKNAME from release-fork file
FORKNAME=$(head -n 1 release-fork)

function release_new() {
  VK_JSON="$DEV_DIR/verifier/openVmVk.json"
  RELEASES_DIR="releases/$FORKNAME"

  # Check if openVmVk.json exists
  if [ ! -f "$VK_JSON" ]; then
    echo "Error: openVmVk.json not found in $DEV_DIR/"
    exit 1
  fi

  # Read verification keys from JSON file
  chunk_vk=$(jq -r '.chunk_vk' "$VK_JSON")
  batch_vk=$(jq -r '.batch_vk' "$VK_JSON")
  bundle_vk=$(jq -r '.bundle_vk' "$VK_JSON")

  # Create directories and copy files
  mkdir -p "$RELEASES_DIR/chunk/$chunk_vk"
  mkdir -p "$RELEASES_DIR/batch/$batch_vk"
  mkdir -p "$RELEASES_DIR/bundle/$bundle_vk"

  # Copy files from releases/dev to the new directories
  cp -r "$DEV_DIR/chunk"/* "$RELEASES_DIR/chunk/$chunk_vk/"
  cp -r "$DEV_DIR/batch"/* "$RELEASES_DIR/batch/$batch_vk/"
  cp -r "$DEV_DIR/bundle"/* "$RELEASES_DIR/bundle/$bundle_vk/"
  mkdir -p $VERIFIER_RELEASES_DIR
  mv $DEV_DIR/* $VERIFIER_RELEASES_DIR

  echo "Files organized for release successfully:"
  echo "  chunk files -> $RELEASES_DIR/chunk/$chunk_vk"
  echo "  batch files -> $RELEASES_DIR/batch/$batch_vk"
  echo "  bundle files -> $RELEASES_DIR/bundle/$bundle_vk"
  echo "  verifier files -> $VERIFIER_RELEASES_DIR"
  echo "  recursivly upload releases directory"

  #aws --profile default s3 cp releases s3://circuit-release/scroll-zkvm --recursive
}

function release_old() {
  aws --profile default s3 cp $DEV_DIR s3://circuit-release/scroll-zkvm/$VERIFIER_RELEASES_DIR --recursive
}

release_new
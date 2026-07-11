#!/bin/bash
set -eu

# Color settings
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  RED="\033[31m"
  GREEN_BOLD="\033[1;32m"
  YELLOW_BOLD="\033[1;33m"
  RED_BOLD="\033[1;31m"
  NC="\033[0m"
else
  RED=""
  GREEN_BOLD=""
  YELLOW_BOLD=""
  RED_BOLD=""
  NC=""
fi
INFO_PREFIX="${GREEN_BOLD}[+]${NC}"
WARN_PREFIX="${YELLOW_BOLD}[!]${NC}"

# select release version
GUEST_VERSION="${GUEST_VERSION:-}"
if [ "$#" -gt 0 ]; then
  GUEST_VERSION="$1"
fi
if [ -z "$GUEST_VERSION" ]; then
  echo -e "$RED_BOLD[x]$NC ${RED}GUEST_VERSION not set$NC"
  exit 1
fi

function can_access_s3() {
  aws --profile default s3 ls "s3://circuit-release/scroll-zkvm/releases/$GUEST_VERSION" >/dev/null 2>&1
}
function download_by_s3() {
  echo -e "$INFO_PREFIX download via s3"
  aws --profile default s3 cp s3://circuit-release/scroll-zkvm/releases/$GUEST_VERSION releases/$GUEST_VERSION --recursive
}

function download_by_http() {
  echo -e "$INFO_PREFIX download via http"
  for f in {chunk,bundle,batch}/{app.{vmexe,elf},openvm.toml} \
    verifier/{openVmVk.json,verifier.bin} \
    bundle/{digest_1.hex,digest_2.hex} \
    axiom_program_ids.json; do
    output_path="releases/$GUEST_VERSION/$f"
    mkdir -p "$(dirname "$output_path")"
    if ! wget --quiet --show-progress -O "$output_path" https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/releases/$GUEST_VERSION/$f; then
      rm -f "$output_path"
      echo -e "$WARN_PREFIX failed to download $f"
      continue
    fi
    echo -e "$INFO_PREFIX downloaded $f"
  done
}

if can_access_s3; then
  download_by_s3
else
  download_by_http
fi
echo -e "$INFO_PREFIX done"
tree "releases/$GUEST_VERSION"

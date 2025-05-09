set -ex
function patch_crates() {
  sed -i 's#git = "https://github.com/openvm-org/openvm.git", rev = "a0ae88f"#git = "ssh://git@github.com/axiom-crypto/openvm-private.git", branch = "patch-v1.2.0"#' Cargo.toml
  sed -i 's#git = "https://github.com/Plonky3/Plonky3.git", rev = "1ba4e5c"#git = "ssh://git@github.com/axiom-crypto/plonky3-private.git", rev = "51704e6036fba6edd58022eb0eceb9f44bc941fb"#' Cargo.toml
  sed -i 's#git = "https://github.com/openvm-org/stark-backend.git", tag = "v1.0.1"#git = "ssh://git@github.com/axiom-crypto/stark-backend-private.git", branch = "patch-v1.1.0"#' Cargo.toml
}

function stage1_stage2() {
  patch_crates
  echo 'BUILD_STAGES=stage1,stage2' > crates/build-guest/.env
  bash build-guest-actions-entrypoint.sh
  git checkout Cargo.toml Cargo.lock
}

function stage3() {
  echo 'BUILD_STAGES=stage3' > crates/build-guest/.env
  make build-guest
}

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: Git has modified tracked files (dirty working tree)." >&2
    echo "Either commit, stash, or discard them before proceeding." >&2
    exit 1
fi
git checkout origin/master Cargo.toml 
stage1_stage2
stage3
#patch_crates

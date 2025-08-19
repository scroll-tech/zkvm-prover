set -euxo pipefail
cargo run --release -p scroll-zkvm-build-guest 2>&1 | tee build.log
make test-e2e-bundle 2>&1 | tee e2e.log

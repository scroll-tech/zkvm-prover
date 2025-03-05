export RUST_MIN_STACK=16777216
# export RUST_LOG=info
export RUSTFLAGS="-Ctarget-feature=+avx2"

export OUTPUT_PATH="e2e_metrics.json"
cargo test --release -p scroll-zkvm-integration --features scroll,bench-metrics --test bundle_circuit e2e -- --exact --nocapture 2>&1 | tee e2e_gpu.log

export RUST_MIN_STACK=16777216
# export RUST_LOG=info
export RUSTFLAGS="-Ctarget-feature=+avx2"

export OUTPUT_PATH="chunk_metrics.json"
cargo test --release -p scroll-zkvm-integration --features scroll,bench-metrics --test chunk_circuit setup_prove_verify_single -- --exact --nocapture 2>&1 | tee chunk-gpu.log

export OUTPUT_PATH="batch_metrics.json"
cargo test --release -p scroll-zkvm-integration --features scroll,bench-metrics --test batch_circuit setup_prove_verify_single -- --exact --nocapture 2>&1 | tee batch-gpu.log

export OUTPUT_PATH="bundle_metrics.json"
cargo test --release -p scroll-zkvm-integration --features scroll,bench-metrics --test bundle_circuit setup_prove_verify -- --exact --nocapture 2>&1 | tee bundle-cpu.log

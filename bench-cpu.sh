export RUST_MIN_STACK=16777216
export RUST_LOG=info
export RUSTFLAGS="-Ctarget-feature=+avx2"

cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup_prove_verify_single -- --exact --nocapture 2>&1 | tee chunk-cpu.log
#cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit setup_prove_verify_single -- --exact --nocapture 2>&1 | tee batch-cpu.log
#cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit setup_prove_verify -- --exact --nocapture 2>&1 | tee bundle-cpu.log

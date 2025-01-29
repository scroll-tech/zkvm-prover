RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --manifest-path crates/circuits/types/Cargo.toml
	@cargo clippy --manifest-path crates/integration/Cargo.toml
	@cargo clippy --manifest-path crates/prover/Cargo.toml
	@cargo clippy --manifest-path crates/tools/flatten-root-proof/Cargo.toml
	@cargo clippy --manifest-path crates/tools/generate-verifier-asm/Cargo.toml
	@cargo clippy --manifest-path crates/verifier/Cargo.toml
	sh openvm-clippy

setup-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup -- --exact --nocapture

test-single-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup_prove_verify -- --exact --nocapture

test-multi-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit multi_chunk -- --exact --nocapture

test-single-batch:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-batch:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit setup_prove_verify_multi -- --exact --nocapture

test-e2e-batch:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-e2e-bundle:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit e2e -- --exact --nocapture

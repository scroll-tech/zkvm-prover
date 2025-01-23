fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --manifest-path crates/circuits/types/Cargo.toml
	@cargo clippy --manifest-path crates/integration/Cargo.toml
	@cargo clippy --manifest-path crates/prover/Cargo.toml
	@cargo clippy --manifest-path crates/verifier/Cargo.toml
	sh openvm-clippy

setup-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup -- --exact --nocapture

test-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup_prove_verify -- --exact --nocapture

test-multi-chunk:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit multi_chunk -- --exact --nocapture

test-batch:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit setup_prove_verify -- --exact --nocapture

test-batch-e2e:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-bundle-e2e:
	@cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit e2e -- --exact --nocapture

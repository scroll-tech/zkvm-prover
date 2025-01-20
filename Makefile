clippy:
	@cargo clippy --features scroll --manifest-path crates/prover/Cargo.toml
	@cargo clippy --features scroll --manifest-path crates/integration/Cargo.toml
	sh openvm-clippy

test-chunk:
	cargo test --release -p scroll-zkvm-integration --features scroll --test chunk_circuit setup_prove_verify -- --exact --nocapture

test-batch:
	cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit setup_prove_verify -- --exact --nocapture

test-batch-e2e:
	cargo test --release -p scroll-zkvm-integration --features scroll --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-bundle-e2e:
	cargo test --release -p scroll-zkvm-integration --features scroll --test bundle_circuit e2e -- --exact --nocapture

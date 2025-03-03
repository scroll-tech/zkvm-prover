RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

RUST_BACKTRACE ?= 1
export RUST_BACKTRACE

RUST_LOG ?= off,scroll_zkvm_integration=debug,scroll_zkvm_verifier=debug,scroll_zkvm_prover=debug,openvm_circuit=debug
export RUST_LOG

ifdef LEGACY
FEATURE := --no-default-features
else
FEATURE := 
endif

$(info FEATURE set to: $(FEATURE))

fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --manifest-path crates/circuits/types/Cargo.toml
	@cargo clippy --manifest-path crates/integration/Cargo.toml
	@cargo clippy --manifest-path crates/prover/Cargo.toml
	@cargo clippy --manifest-path crates/verifier/Cargo.toml
	sh openvm-clippy

build-guest:
	@cargo run --release -p scroll-zkvm-build-guest $(FEATURE)

test-execute-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test chunk_circuit test_execute -- --exact --nocapture

test-cycle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test chunk_circuit test_cycle -- --exact --nocapture

test-execute-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test batch_circuit test_execute -- --exact --nocapture

test-execute-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test bundle_circuit test_execute -- --exact --nocapture

test-single-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test chunk_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test chunk_circuit setup_prove_verify_multi -- --exact --nocapture

test-single-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test batch_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test batch_circuit setup_prove_verify_multi -- --exact --nocapture

test-e2e-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-e2e-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --features scroll --test bundle_circuit e2e -- --exact --nocapture

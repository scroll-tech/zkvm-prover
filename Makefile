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

download-release:
	sh download-release.sh

fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --tests --manifest-path crates/circuits/types/Cargo.toml -- -D warnings
	sh openvm-clippy.sh
	@cargo clippy --tests --all-features --manifest-path crates/verifier/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/prover/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/integration/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/build-guest/Cargo.toml -- -D warnings

clean-guest:
	docker stop build-guest
	docker rm build-guest
	docker rmi build-guest:local

build-guest:
	sh build-guest.sh

clean-build-guest: clean-guest build-guest

profile-chunk:
	@GUEST_PROFILING=true cargo test --release -p scroll-zkvm-integration --test chunk_circuit guest_profiling -- --exact --nocapture

test-execute-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test chunk_circuit test_execute -- --exact --nocapture

test-execute-chunk-multi:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test chunk_circuit test_execute_multi -- --exact --nocapture

test-cycle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test chunk_circuit test_cycle -- --exact --nocapture

test-execute-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test batch_circuit test_execute -- --exact --nocapture

test-execute-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test bundle_circuit test_execute -- --exact --nocapture

test-single-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test chunk_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-chunk:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test chunk_circuit setup_prove_verify_multi -- --exact --nocapture

test-single-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test batch_circuit setup_prove_verify_single -- --exact --nocapture

test-e2e-batch:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-bundle-local:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test bundle_circuit setup_prove_verify_local_task -- --exact --nocapture

test-e2e-bundle:
	@cargo test --release -p scroll-zkvm-integration $(FEATURE) --test bundle_circuit e2e -- --exact --nocapture

RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

RUST_BACKTRACE ?= 1
export RUST_BACKTRACE

RUST_LOG ?= off,scroll_zkvm_integration=debug,scroll_zkvm_verifier=debug,scroll_zkvm_prover=debug,openvm_circuit=debug
export RUST_LOG

OPENVM_RUST_TOOLCHAIN ?= nightly-2025-08-18
export OPENVM_RUST_TOOLCHAIN

TESTDATA_PATH := crates/integration/testdata/phase2
CHUNK_PROOF := 1-4

$(info TESTDATA_PATH set to: $(TESTDATA_PATH))

download-release:
	sh download-release.sh

fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --tests --manifest-path crates/types/Cargo.toml -- -D warnings
	sh openvm-clippy.sh
	@cargo clippy --tests --all-features --manifest-path crates/verifier/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/prover/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/integration/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/build-guest/Cargo.toml -- -D warnings

clean-guest:
	docker rmi build-guest:local

build-guest:
	sh build-guest.sh

build-guest-local:
	cargo run --release -p scroll-zkvm-build-guest

clean-build-guest: clean-guest build-guest

clean-test-cache:
	@rm -f $(TESTDATA_PATH)/proofs/*.json

$(TESTDATA_PATH)/proofs/chunk-%.json:
	@OUTPUT_DIR=$(realpath $(TESTDATA_PATH)/proofs) $(MAKE) test-single-chunk
	cp -f $(TESTDATA_PATH)/proofs/chunk/proofs/*.json $(TESTDATA_PATH)/proofs

profile-chunk:
	@GUEST_PROFILING=true cargo test --release -p scroll-zkvm-integration --test chunk_circuit guest_profiling -- --exact --nocapture

export-onchain-verifier:
	@cargo test --release -p scroll-zkvm-integration --test onchain_verifier export_onchain_verifier -- --exact --nocapture

test-execute-chunk:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit test_execute -- --exact --nocapture

test-execute-chunk-multi:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit test_execute_multi -- --exact --nocapture

test-cycle:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit test_cycle -- --exact --nocapture

test-execute-batch: $(TESTDATA_PATH)/proofs/chunk-$(CHUNK_PROOF).json
	@cargo test --release -p scroll-zkvm-integration --test batch_circuit test_e2e_execute -- --exact --nocapture

test-execute-batch-fast: $(TESTDATA_PATH)/tasks/batch-task.json
	@cargo test --release -p scroll-zkvm-integration --test batch_circuit test_execute -- --exact --nocapture

test-execute-bundle:
	@cargo test --release -p scroll-zkvm-integration --test bundle_circuit test_execute -- --exact --nocapture

test-single-chunk:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-chunk:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit setup_prove_verify_multi -- --exact --nocapture

test-single-batch: $(TESTDATA_PATH)/tasks/batch-task.json
	@cargo test --release -p scroll-zkvm-integration --test batch_circuit setup_prove_verify_single -- --exact --nocapture

test-e2e-batch:
	@cargo test --release -p scroll-zkvm-integration --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test --release -p scroll-zkvm-integration --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-bundle-local:
	@cargo test --release -p scroll-zkvm-integration --test bundle_circuit setup_prove_verify_local_task -- --exact --nocapture

test-e2e-bundle:
	@cargo test --release -p scroll-zkvm-integration --test bundle_circuit e2e -- --exact --nocapture

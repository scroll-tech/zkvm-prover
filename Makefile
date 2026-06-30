RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

RUST_BACKTRACE ?= 1
export RUST_BACKTRACE

RUST_LOG ?= off,scroll_zkvm_integration=debug,scroll_zkvm_verifier=debug,scroll_zkvm_prover=debug,p3_fri=warn,p3_dft=warn,openvm_circuit=warn
export RUST_LOG

OPENVM_RUST_TOOLCHAIN ?= nightly-2025-08-18
export OPENVM_RUST_TOOLCHAIN

# Set GPU config if GPU=1 is set
ifeq ($(GPU),1)
CARGO_CONFIG_FLAG = --features scroll-zkvm-integration/cuda
else
CARGO_CONFIG_FLAG =
endif

SRS_PARAMS_DIR := $(HOME)/.openvm/params
SRS_PARAMS_URL := https://circuit-release.s3.us-west-2.amazonaws.com/scroll-zkvm/params
SRS_PARAMS := $(SRS_PARAMS_DIR)/kzg_bn254_22.srs $(SRS_PARAMS_DIR)/kzg_bn254_24.srs

# Download params if missing
$(SRS_PARAMS_DIR)/%.srs:
	@mkdir -p $(SRS_PARAMS_DIR)
	@if [ ! -f "$@" ]; then \
		echo "Fetching $(@F) from $(SRS_PARAMS_URL)"; \
		wget -q -O "$@" "$(SRS_PARAMS_URL)/$(@F)"; \
	fi

download-release:
	bash download-release.sh

fmt:
	@cargo fmt --all

clippy:
	@cargo clippy --tests --manifest-path crates/types/Cargo.toml -- -D warnings
	sh openvm-clippy.sh
	@cargo clippy --tests --all-features --manifest-path crates/verifier/Cargo.toml -- -D warnings
	@cargo clippy --tests --manifest-path crates/prover/Cargo.toml -- -D warnings
	@cargo clippy --tests --manifest-path crates/integration/Cargo.toml -- -D warnings
	@cargo clippy --tests --all-features --manifest-path crates/build-guest/Cargo.toml -- -D warnings

clean-guest:
	docker rmi build-guest:local

build-guest:
	sh build-guest.sh

build-guest-local:
	cargo run --release -p scroll-zkvm-build-guest

build-guest-sp1:
	cd sp1 && cargo run --release -p scroll-zkvm-build-guest-sp1
	cd sp1 && cargo build --release -p scroll-zkvm-sp1-prover-test
	mkdir -p sp1/releases/dev/sp1/verifier
	cp -r sp1/verifier/lib/sp1-contracts/contracts/src/v6.1.0/* sp1/releases/dev/sp1/verifier/
	@echo "SP1 verifier contract copied to sp1/releases/dev/sp1/verifier/"

test-e2e-sp1-chunk:
	cd sp1 && CUDA_VISIBLE_DEVICES=$(CUDA_VISIBLE_DEVICES) ./run-gpu-prover.sh --circuit chunk

test-e2e-sp1-batch:
	cd sp1 && CUDA_VISIBLE_DEVICES=$(CUDA_VISIBLE_DEVICES) ./run-gpu-prover.sh --circuit batch

test-e2e-sp1-bundle:
	cd sp1 && CUDA_VISIBLE_DEVICES=$(CUDA_VISIBLE_DEVICES) ./run-gpu-prover-e2e.sh
	cd sp1/verifier && forge test --match-test testVerifyBundleProof

clean-build-guest: clean-guest build-guest

profile-chunk:
	@GUEST_PROFILING=true cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit guest_profiling -- --exact --nocapture

export-onchain-verifier:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test onchain_verifier export_onchain_verifier -- --exact --nocapture

test-execute-chunk:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_execute -- --exact --nocapture

test-execute-chunk-multi:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_execute_multi -- --exact --nocapture

test-execute-validium-chunk:
	@cargo test --release -p scroll-zkvm-integration --test chunk_circuit test_execute_validium -- --exact --nocapture

bench-execute-chunk:
	@cargo run --release -p scroll-zkvm-integration --bin chunk-benchmark --features perf-metrics -- --profiling

test-cycle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_cycle -- --exact --nocapture

test-execute-batch:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit test_e2e_execute -- --exact --nocapture

test-execute-batch-fast:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit test_execute -- --exact --nocapture

test-execute-bundle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test bundle_circuit test_execute -- --exact --nocapture

test-execute-validium-e2e:
	@cargo test --release -p scroll-zkvm-integration --test bundle_circuit test_execute_validium -- --exact --nocapture

test-single-chunk:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit setup_prove_verify_single -- --exact --nocapture

test-multi-chunk:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit setup_prove_verify_multi -- --exact --nocapture

test-single-batch:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit setup_prove_verify_single -- --exact --nocapture

test-e2e-batch:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit e2e -- --exact --nocapture

test-bundle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test bundle_circuit setup_prove_verify -- --exact --nocapture

test-bundle-local:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test bundle_circuit setup_prove_verify_local_task -- --exact --nocapture

test-e2e-bundle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test bundle_circuit e2e -- --exact --nocapture

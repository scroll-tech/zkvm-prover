ifndef RUST_TARGET
RUST_TARGET := $(if $(CARGO_BUILD_TARGET),$(CARGO_BUILD_TARGET),\
                $(if $(TARGET),$(TARGET),\
                  $(shell rustc -vV | sed -n 's/^host: //p')))
endif
RUST_TARGET_ARCH := $(firstword $(subst -, ,$(RUST_TARGET)))
$(info Target: $(RUST_TARGET) ($(RUST_TARGET_ARCH)))

ifeq ($(RUST_TARGET_ARCH),x86_64)
  EXTRA_RUSTFLAGS := -C target-feature=+avx2
  ifeq (,$(findstring $(EXTRA_RUSTFLAGS),$(RUSTFLAGS)))
    RUSTFLAGS := $(strip $(RUSTFLAGS) $(EXTRA_RUSTFLAGS))
  endif
  export RUSTFLAGS
endif
$(info RUSTFLAGS: $(RUSTFLAGS))

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

download-release:
	sh download-release.sh

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

clean-build-guest: clean-guest build-guest

profile-chunk:
	@GUEST_PROFILING=true cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit guest_profiling -- --exact --nocapture

export-onchain-verifier:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test onchain_verifier export_onchain_verifier -- --exact --nocapture

test-execute-chunk:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_execute -- --exact --nocapture

test-ceno-scroll-chunk:
	@cargo run --release --features scroll -p ceno-integration-test -- --exact --nocapture

test-ceno-ethereum-chunk:
	@cargo run --release -p ceno-integration-test -- --exact --nocapture

test-execute-chunk-multi:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_execute_multi -- --exact --nocapture

test-cycle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test chunk_circuit test_cycle -- --exact --nocapture

test-execute-batch:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit test_e2e_execute -- --exact --nocapture

test-execute-batch-fast:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test batch_circuit test_execute -- --exact --nocapture

test-execute-bundle:
	@cargo test $(CARGO_CONFIG_FLAG) --release -p scroll-zkvm-integration --test bundle_circuit test_execute -- --exact --nocapture

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

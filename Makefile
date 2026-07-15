RUST_MIN_STACK ?= 16777216
export RUST_MIN_STACK

RUST_BACKTRACE ?= 1
export RUST_BACKTRACE

RUST_LOG ?= off,scroll_zkvm_integration=debug,scroll_zkvm_verifier=debug,scroll_zkvm_prover=debug,p3_fri=warn,p3_dft=warn,openvm_circuit=warn
export RUST_LOG

OPENVM_RUST_TOOLCHAIN ?= nightly-2025-08-18
export OPENVM_RUST_TOOLCHAIN

CENO_RUST_TOOLCHAIN ?= +nightly-2025-11-20
export CENO_RUST_TOOLCHAIN

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

# ---- ZisK backend (see zisk/AGENTS.md and docs/zisk-backend-assessment.md) ----
# Requires the ZisK toolchain on PATH: export PATH="$$HOME/.zisk/bin:$$PATH"
build-guest-zisk:
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-build-guest-zisk
	cd zisk && cargo build --release -p scroll-zkvm-zisk-prover-test -p scroll-zkvm-zisk-recursion-test

bench-zisk-chunk:
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-zisk-prover-test -- --circuit chunk

# Attempt an actual proof (needs the STARK proving key: ziskup --provingkey).
# Defaults to GPU on this machine; use --emulator for a CPU proof with the prebuilt emulator.
prove-zisk-chunk:
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-zisk-prover-test -- --circuit chunk --prove --gpu

prove-zisk-chunk-cpu:
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-zisk-prover-test -- --circuit chunk --prove --emulator

# ---- Ceno backend (see ceno/AGENTS.md) ----
CENO_PROVER_FEATURES ?= gpu,jemalloc,aot-x86_64,parallel
CENO_MAX_CELL_PER_SHARD ?= 1245708288
CENO_CARGO_ENV = CARGO_NET_GIT_FETCH_WITH_CLI=true
CENO_GPU_E2E_ENV = $(CENO_CARGO_ENV) RUSTFLAGS="-C target-feature=+avx2" JEMALLOC_SYS_WITH_MALLOC_CONF=retain:true,background_thread:true,metadata_thp:always,thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true RUST_MIN_STACK=536870912 CENO_EMULATOR_BACKEND=aot CENO_GPU_ENABLE_WITGEN=0 CENO_GPU_WITGEN=0 CENO_CONCURRENT_CHIP_PROVING=1 CENO_GPU_MEM_TRACKING=0 CENO_GPU_CACHE_LEVEL=1 CENO_GPU_JAGGED_RESHAPE_LOG_HEIGHT=23 CENO_GPU_LARGE_TASK_BOOKING_MARGIN_MB=3048 CENO_MAX_CELL_PER_SHARD=$(CENO_MAX_CELL_PER_SHARD)

build-guest-ceno:
	cd ceno && $(CENO_CARGO_ENV) cargo run --release -p scroll-zkvm-build-guest-ceno -- --mode force
	cd ceno && $(CENO_CARGO_ENV) RUSTFLAGS="-C target-feature=+avx2" JEMALLOC_SYS_WITH_MALLOC_CONF=retain:true,background_thread:true,metadata_thp:always,thp:always,dirty_decay_ms:10000,muzzy_decay_ms:10000,abort_conf:true cargo build --release -p scroll-zkvm-ceno-prover-test --features $(CENO_PROVER_FEATURES)

test-e2e-ceno-chunk:
	@if [ "$(GPU)" != "1" ]; then echo "GPU=1 is required for Ceno GPU E2E"; exit 1; fi
	cd ceno && $(CENO_GPU_E2E_ENV) cargo run --release -p scroll-zkvm-ceno-prover-test --features $(CENO_PROVER_FEATURES) -- --circuit chunk --gpu

test-e2e-ceno-batch:
	@if [ "$(GPU)" != "1" ]; then echo "GPU=1 is required for Ceno GPU E2E"; exit 1; fi
	cd ceno && $(CENO_GPU_E2E_ENV) cargo run --release -p scroll-zkvm-ceno-prover-test --features $(CENO_PROVER_FEATURES) -- --circuit batch --gpu

test-e2e-ceno-bundle:
	@if [ "$(GPU)" != "1" ]; then echo "GPU=1 is required for Ceno GPU E2E"; exit 1; fi
	cd ceno && $(CENO_GPU_E2E_ENV) cargo run --release -p scroll-zkvm-ceno-prover-test --features $(CENO_PROVER_FEATURES) -- --circuit bundle --gpu

# In-guest recursion PoC: prove the bundle stub, then verify that child proof inside
# the batch recursion guest via zisk-verifier. We use the prebuilt emulator (`-l`) because
# the ASM microservice path times out on this machine for tiny proofs.
recursion-poc-zisk: build-guest-zisk
	python3 -c "import struct; p=b'\\x00\\x01\\x02\\x03'; buf=struct.pack('<Q',len(p))+p; buf+=b'\\x00'*(-len(buf)%8); open('zisk/releases/dev/zisk/prover-test/bundle_input_framed.bin','wb').write(buf)"
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-zisk-recursion-test -- prove-child \
		--elf releases/dev/zisk/bundle/app \
		--input releases/dev/zisk/prover-test/bundle_input_framed.bin \
		--output releases/dev/zisk/prover-test/bundle_child_proof.bin \
		--minimal --emulator
	cd zisk && PATH="$$HOME/.zisk/bin:$$PATH" cargo run --release -p scroll-zkvm-zisk-recursion-test -- verify-in-guest \
		--proof releases/dev/zisk/prover-test/bundle_child_proof.bin \
		--batch-elf releases/dev/zisk/batch/app

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

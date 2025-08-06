# Scroll zkVM

**zkVM-based Circuits (Guest Programs) with a complete Scroll Prover implementation**

## Repository

This repository contains the following member crates:

- [scroll-zkvm-types](./crates/circuits/types): Primitive and Common types used in project and being exported. It is an aggregation of a series of crates:
  + [scroll-zkvm-types-base](./crates/circuits/types/base): Common types which is used project-wide and expected to be recognized beyond project
  + [scroll-zkvm-types-base](./crates/circuits/types/chunk): Like the base crate, but in the project, these types are only related to chunk circuit
  + [scroll-zkvm-types-base](./crates/circuits/types/batch): Like the base crate, but in the project, these types are only related to batch circuit
  + [scroll-zkvm-types-base](./crates/circuits/types/bundle): Like the base crate, but in the project, these types are only related to bundle circuit
- [scroll-zkvm-chunk-circuit](./crates/circuits/chunk-circuit): Circuit for verification of a Scroll [chunk](TODO:doc)
- [scroll-zkvm-batch-circuit](./crates/circuits/batch-circuit): Circuit for verification of a Scroll [batch](TODO:doc)
- [scroll-zkvm-bundle-circuit](./crates/circuits/bundle-circuit): Circuit for verification of a Scroll [bundle](TODO:doc)
- [scroll-zkvm-prover](./crates/prover): Implementation for a Scroll Prover
- [scroll-zkvm-verifier](./crates/verifier): Implementation for a Verifier-only mode
- [scroll-zkvm-integration](./crates/integration): Integration tests for the Scroll Prover

## Overview

The Scroll zkVM Circuits are [openvm](https://book.openvm.dev/) based Guest Programs.

The [prover](./crates/prover) crate offers a minimalistic API for setting up, generating and verifying proofs for Scroll's zk-rollup.

For a deeper dive into our implementation, please refer the [interfaces](./docs/interfaces.md) doc.

## Testing

For more commands please refer the [Makefile](./Makefile).

### Build Guest Programs

In case you have made any changes to the guest programs, it is important to build them before running the tests.

```shell
$ make build-guest
```

Upon building the guest programs, the child commitments in [batch-circuit](./crates/circuits/batch-circuit/src/child_commitments.rs) and [bundle-circuit](./crates/circuits/bundle-circuit/src/child_commitments.rs) will be overwritten by `build-guest`.

### End-to-end tests for chunk-prover

```shell
$ make test-single-chunk
```

### End-to-end tests for batch-prover

```shell
$ make test-e2e-batch
```

### End-to-end tests for bundle-prover

```shell
$ make test-e2e-bundle
```

*Note*: Configure `RUST_LOG=debug` for debug logs or `RUST_LOG=none,scroll_zkvm_prover=debug` for logs specifically from the `scroll-zkvm-prover` crate.

## Usage of Prover API

### Dependency

Add the following dependency in your `Cargo.toml`:

```toml
[dependencies]
scroll-zkvm-prover = { git = "https://github.com/scroll-tech/zkvm-prover", branch = "master" }
```

### To prove a universal task with STARK proofs

Prover capable of generating STARK proofs for a Scroll [universal task](TODO:doc):

```rust
use std::path::Path;

use scroll_zkvm_prover::{
    Prover,
    task::ProvingTask,
};
use scroll_zkvm_types::{
    public_inputs::ForkName,
    chunk::ChunkWitness,
    task::ProvingTask as UniversalProvingTask,
};

// Paths to the application exe and application config.
let path_exe = Path::new("./path/to/app.vmexe");
let path_app_config = Path::new("./path/to/openvm.toml");

// Optional directory to cache generated proofs on disk.
let cache_dir = Path::new("./path/to/cache/proofs");

let config = scroll_zkvm_prover::ProverConfig {
    path_app_exe,
    path_app_config,
    dir_cache: Some(cache_dir),
    ..Default::default()
};
// Setup prover.
let prover = Prover::setup(config, false, None)?;

let vk = prover.get_app_vk();
let task : UniversalProvingTask = /* a universal task, commonly generated and assigned by coordinator */

// Generate a proof.
let proof = prover.gen_proof_universal(&task, false)?;

// Verify proof.
let verifier = prover.dump_universal_verifier(None::<String>);
assert!(verifier.verify_proof(proof.as_root_proof().expect("should be root proof"), &vk)?);
```

### To prove a universal task with SNARK proofs

Prover capable of generating SNARK proofs aggregating the root proof for a Scroll [universal task](TODO:doc):

```rust
use std::path::Path;

use scroll_zkvm_prover::{
    Prover,
    task::ProvingTask,
};
use scroll_zkvm_types::{
    public_inputs::ForkName,
    chunk::ChunkWitness,
    task::ProvingTask as UniversalProvingTask,
};

// Paths to the application exe and application config.
let path_exe = Path::new("./path/to/app.vmexe");
let path_app_config = Path::new("./path/to/openvm.toml");

// Optional directory to cache generated proofs on disk.
let cache_dir = Path::new("./path/to/cache/proofs");

let config = scroll_zkvm_prover::ProverConfig {
    path_app_exe,
    path_app_config,
    dir_cache: Some(cache_dir),
    ..Default::default()
};
// Setup prover capable to generate SNARK proof.
let prover = Prover::setup(config, true, None)?;

let vk = prover.get_app_vk();
let task : UniversalProvingTask = /* a universal task, commonly generated and assigned by coordinator */

// Generate a SNARK proof.
let proof = prover.gen_proof_universal(&task, true)?;

// Verify proof.
let verifier = prover.dump_universal_verifier(None::<String>);
assert!(verifier.verify_proof_evm(&proof.clone().into_evm_proof().expect("should be evm proof").into(), &vk)?);
```

### Form a universal task for a chunk from block witnesses

A universal task for proving a chunk can be easily generated from block witnesses:

```rust
use std::path::Path;

use scroll_zkvm_prover::{
    Prover,
    task::ProvingTask,
};
use scroll_zkvm_types::{
    public_inputs::ForkName,
    chunk::ChunkWitness,
    task::ProvingTask as UniversalProvingTask,
};

let prover = /* init a prover and load the chunk circuit */
let vk = prover.get_app_vk();

// Proving task of a chunk with 3 blocks.
let block_witnesses = vec![
    sbv::primitives::types::BlockWitness { /* */ },
    sbv::primitives::types::BlockWitness { /* */ },
    sbv::primitives::types::BlockWitness { /* */ },
];
let wit = ChunkWitness::new(
    &block_witnesses,
    template_wit.prev_msg_queue_hash,
    template_wit.fork_name,
);

let task = UniversalProvingTask{
    serialized_witness: vec![wit.rkyv_serialize(None)],
    aggregated_proofs: Vec::new(),
    fork_name: "feynman".to_string(),
    vk: vk.clone(),
    identifier: Default::default(),
};

```



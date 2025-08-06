#!/bin/bash

mkdir -p releases
rm -rf releases/dev

# run crates/build-guest
cargo run --release -p scroll-zkvm-build-guest

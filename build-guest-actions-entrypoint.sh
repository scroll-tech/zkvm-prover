#!/bin/bash

# read arg to know if we are in github actions
IS_ACTIONS=$1

# config to stop dubious ownership warning
if [ "$IS_ACTIONS" = "true" ]; then
  echo "github actions running"
  git config --global --add safe.directory $PWD
fi

# run crates/build-guest
cargo run --release -p scroll-zkvm-build-guest

# set the github actions outputs for the metadata action.yml
if [ "$IS_ACTIONS" = "true" ]; then
  echo "github actions running"

  {
    echo 'commitments-chunk<<EOF'
    cat crates/prover/src/commitments/chunk.rs
    echo EOF
  } >> $GITHUB_OUTPUT

  {
    echo 'commitments-batch<<EOF'
    cat crates/prover/src/commitments/batch.rs
    echo EOF
  } >> $GITHUB_OUTPUT

  {
    echo 'commitments-bundle<<EOF'
    cat crates/prover/src/commitments/bundle.rs
    echo EOF
  } >> $GITHUB_OUTPUT
fi

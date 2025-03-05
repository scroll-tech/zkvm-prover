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

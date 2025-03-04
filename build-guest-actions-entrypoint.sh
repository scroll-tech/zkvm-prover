git config --global --add safe.directory $PWD

cargo run --release -p scroll-zkvm-build-guest

commitments_chunk=$(cat crates/prover/src/commitments/chunk.rs)
commitments_batch=$(cat crates/prover/src/commitments/batch.rs)
commitments_bundle=$(cat crates/prover/src/commitments/bundle.rs)

echo "commitments-chunk=$commitments_chunk" >> $GITHUB_OUTPUT
echo "commitments-batch=$commitments_batch" >> $GITHUB_OUTPUT
echo "commitments-bundle=$commitments_bundle" >> $GITHUB_OUTPUT

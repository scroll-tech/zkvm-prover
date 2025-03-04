cargo run --release -p scroll-zkvm-build-guest

shasum_chunk=$(shasum crates/prover/src/commitments/chunk.rs | awk '{ print $1 }')
shasum_batch=$(shasum crates/prover/src/commitments/batch.rs | awk '{ print $1 }')
shasum_bundle=$(shasum crates/prover/src/commitments/bundle.rs | awk '{ print $1 }')

echo "shasum-chunk=$shasum_chunk" >> $GITHUB_OUTPUT
echo "shasum-batch=$shasum_batch" >> $GITHUB_OUTPUT
echo "shasum-bundle=$shasum_bundle" >> $GITHUB_OUTPUT

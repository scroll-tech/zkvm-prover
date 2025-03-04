# build docker image
docker build --platform linux/amd64 -t build-guest:local .

# run docker image
docker run --platform linux/amd64 --name build-guest build-guest:local

# copy commitments from container to local (prover)
docker cp build-guest:/app/crates/prover/src/commitments/chunk.rs crates/prover/src/commitments/chunk.rs
docker cp build-guest:/app/crates/prover/src/commitments/batch.rs crates/prover/src/commitments/batch.rs
docker cp build-guest:/app/crates/prover/src/commitments/bundle.rs crates/prover/src/commitments/bundle.rs

# copy commitments to local (verifier)
cp crates/prover/src/commitments/chunk.rs crates/verifier/src/commitments/chunk.rs
cp crates/prover/src/commitments/batch.rs crates/verifier/src/commitments/batch.rs
cp crates/prover/src/commitments/bundle.rs crates/verifier/src/commitments/bundle.rs

# copy commitments to local (circuits)
cp crates/prover/src/commitments/chunk.rs crates/circuits/batch-circuit/src/child_commitments.rs
cp crates/prover/src/commitments/batch.rs crates/circuits/bundle-circuit/src/child_commitments.rs

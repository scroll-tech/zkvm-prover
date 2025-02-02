# release version
if [[ -z "${SCROLL_ZKVM_VERSION}" ]]; then
  echo "SCROLL_ZKVM_VERSION not set"
  exit 1
else
  DIR_OUTPUT="releases/${SCROLL_ZKVM_VERSION}"
fi

# directory to read assets from
if [[ -z "${SCROLL_ZKVM_TESTRUN_DIR}" ]]; then
  echo "SCROLL_ZKVM_TESTRUN_DIR not set"
  exit 1
else
  DIR_INPUT="${SCROLL_ZKVM_TESTRUN_DIR}"
fi

# create all required directories for release
mkdir -p $DIR_OUTPUT/chunk
mkdir -p $DIR_OUTPUT/batch
mkdir -p $DIR_OUTPUT/bundle

# copy chunk-program related assets
cp $DIR_INPUT/chunk/app.vmexe $DIR_OUTPUT/chunk/app.vmexe
cp $DIR_INPUT/chunk/app.pk $DIR_OUTPUT/chunk/app.pk
cp $DIR_INPUT/chunk/openvm.toml $DIR_OUTPUT/chunk/openvm.toml

# copy batch-program related assets
cp $DIR_INPUT/batch/app.vmexe $DIR_OUTPUT/batch/app.vmexe
cp $DIR_INPUT/batch/app.pk $DIR_OUTPUT/batch/app.pk
cp $DIR_INPUT/batch/openvm.toml $DIR_OUTPUT/batch/openvm.toml

# copy bundle-program related assets
cp $DIR_INPUT/bundle/app.vmexe $DIR_OUTPUT/bundle/app.vmexe
cp $DIR_INPUT/bundle/app.pk $DIR_OUTPUT/bundle/app.pk
cp $DIR_INPUT/bundle/openvm.toml $DIR_OUTPUT/bundle/openvm.toml
cp $DIR_INPUT/bundle/verifier.bin $DIR_OUTPUT/bundle/verifier.bin
cp $DIR_INPUT/bundle/verifier.sol $DIR_OUTPUT/bundle/verifier.sol
xxd -l 32 -p $DIR_INPUT/bundle/digest_1 | tr -d '\n' | awk '{gsub("%", ""); print}' > $DIR_OUTPUT/bundle/digest_1.hex
xxd -l 32 -p $DIR_INPUT/bundle/digest_2 | tr -d '\n' | awk '{gsub("%", ""); print}' > $DIR_OUTPUT/bundle/digest_2.hex

# upload to s3
aws --profile default s3 cp $DIR_OUTPUT s3://circuit-release/scroll-zkvm/$DIR_OUTPUT --recursive

CIRCUIT_VERSION="0.1.0-rc.4"

function download() {
  OUT=release-${CIRCUIT_VERSION}
  aws --profile default s3 cp s3://circuit-release/scroll-zkvm/$OUT $OUT --recursive
}

download

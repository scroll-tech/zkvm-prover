set -xe
pushd `bash $(dirname $0)/locate-crate.sh $1`
git diff | cat
git checkout .
popd
cargo clean -p $1
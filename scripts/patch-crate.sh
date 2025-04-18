set -xe
patch=`realpath $2`
pushd `bash $(dirname $0)/locate-crate.sh $1`
git apply $patch
git diff | cat
popd
cargo clean -p $1
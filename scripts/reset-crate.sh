crate=`cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "'$1'") | select(.manifest_path ) | .manifest_path' | sort | head -n 1`
workspace=$(echo $crate | sed 's#crates.*#Cargo.toml#')
echo `dirname $workspace`
exit 0
cd `dirname $workspace`
git diff | cat
git checkout .
cargo clean -p $1
#echo $crate
crate=`cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "'$1'") | select(.manifest_path ) | .manifest_path' | sort | head -n 1`
workspace=$(echo $crate | sed 's#crates.*#Cargo.toml#')
dirname $workspace
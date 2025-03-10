# fmt: shfmt -w -i 4 scripts/update-openvm.sh

SED='s#rev = \"333b367\"#rev = \"485caec\"#'
#SED='s#rev = \"f1b4844\"#tag = \"v1.0.0-rc.1\"#'

function update_openvm() {
    pkgs="tiny-keccak revm alloy-primitives"
    for pkg in $pkgs; do
        crate=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "'$pkg'") | select(.manifest_path | contains("git")) | .manifest_path')
        workspace=$(echo $crate | sed 's#crates.*#Cargo.toml#')
        echo updating $crate
        echo updating $workspace
        sed -i "$SED" "$crate" "$workspace" 
        cargo clean -p $pkg
    done
    sed -i "$SED" Cargo.toml
    cargo update
}

update_openvm

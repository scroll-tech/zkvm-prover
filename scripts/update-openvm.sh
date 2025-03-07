# fmt: shfmt -w -i 4 scripts/print-patch.sh

SED='s#tag = \"v1.0.0-rc.1\"#rev = \"f1b4844\"#'
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
}

update_openvm

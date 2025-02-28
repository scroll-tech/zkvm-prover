# fmt: shfmt -w -i 4 scripts/print-patch.sh
function update() {
    PKG=$1
    crate=$(cargo metadata --format-version=1 | jq -r '.packages[] | select(.name == "'$PKG'") | select(.manifest_path | contains("git")) | .manifest_path')
    workspace=$(echo $crate | sed 's#crates.*#Cargo.toml#')
    echo updating $crate
    echo updating $workspace
    sed -i "s#$2#$3#" $crate $workspace 
}

function update_openvm() {
    pkgs="tiny-keccak revm alloy-primitives"
    for pkg in $pkgs; do
        update $pkg $1 $2
    done
    sed -i "s#$1#$2#" Cargo.toml
}

update_openvm 7c63d20 f1b4844

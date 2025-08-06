echo $1 -> $2
# version: solc-linux-amd64-v0.8.19+commit.7dd6d404
cat $1 | solc --bin - | grep 6080 | xxd -r -p > $2

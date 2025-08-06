echo $1 -> $2
cat $1 | solc --bin - | grep 6080 | xxd -r -p > $2

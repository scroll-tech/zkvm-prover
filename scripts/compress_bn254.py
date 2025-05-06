# This script compresses a list of u32 integers into a single hex string (bn254).
# It reads from generated commitment files, such as crates/circuits/batch-circuit/batch_exe_commit.rs,
# and outputs the compressed hex string. 
# It can be used to verify the generated bundle-circuit/digest_{1,2} files.
import json 
import sys
import re

def compress(arr): 
    return sum(v * pow(2013265921, i) for i, v in enumerate(arr))

pattern = r'\[\s*\d+\s*(,\s*\d+\s*)*\]'
code = open(sys.argv[1]).read()
matched = re.search(pattern, code).group(0)
arr = json.loads(matched)
f = compress(arr)
h = f.to_bytes(32, 'big').hex()
print(h)

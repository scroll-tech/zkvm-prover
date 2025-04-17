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

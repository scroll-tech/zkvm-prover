import json 
import sys

def compress(arr): 
    return sum(v * pow(2013265921, i) for i, v in enumerate(arr))

arr = json.loads(open(sys.argv[1]).read())
f = compress(arr)
h = f.to_bytes(32, 'big').hex()
print(h)

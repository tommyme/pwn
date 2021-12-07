target="pwnme2"
import os
j = os.path.join
path = j(".target",target)
is_32bit = lambda path: len(os.popen(f"file {path} | grep 32-bit").read()) > 0
bit_32 = is_32bit(path)
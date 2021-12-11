target="gyctf_2020_force"
import os
j = os.path.join
path = j(".target",target)
is_32bit = lambda path: len(os.popen(f"file {path} | grep 32-bit").read()) > 0
bit_32 = is_32bit(path)
pickle_cache = ".helper"


if __name__ == "__main__":
    print("32bit:",bit_32)
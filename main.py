# from LibcSearcher import *
from helper import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
loader = Loader("test", 64, debug=True)
loader.patch_AIO(2.27)
elf,libc = loader.init()
# libc = ELF("buuoj/18/64/libc.so.6")
io = loader.process()
# io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())


def add(size,content):
    sla(b">",b"1")
    sla(b">",bt(size))
    sla(b">",content)

def free(id):
    sla(b">",b"2")
    sla(b">",bt(id))

def show(id):
    sla(b">",b"3")
    sla(b">",bt(id))

# trunk array [addr, size]
# add max=10
#     malloc(0xf8)
#     get size <= 0xf8
#     get content
# free
#     set 0
#     free
#     [addr, size] = 0
# show
#     puts

# feature 1: off by one
# add(0xf8,b'aaaa'), add(0xf8,b"bbbb"), free(0)
# add(0xf8,b"cccc"), pause()

# for i in range(10):
#     add(0x8, b"xxxx")



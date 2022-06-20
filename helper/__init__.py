from helper.elf_loader import Loader
from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
from typing import Union
import os
from .arg import args


context.terminal = ['wt.exe', '-w', '0', 'sp', 'wsl', '-e']

loader = Loader(args)
elf,libc,rop = loader.init()
io = loader.process()
# abbreviations
r      = io.recv
rl     = io.recvline
ru     = lambda x : io.recvuntil(to_bytes(x))
shell  = io.interactive
s      = lambda x : io.send(to_bytes(x))
sl     = lambda x : io.sendline(to_bytes(x))
sa     = lambda x, y : io.sendafter(to_bytes(x), to_bytes(y))
sla    = lambda x, y : io.sendlineafter(to_bytes(x), to_bytes(y))
uu32   = lambda data : u32(data.ljust(4,b'\x00'))
uu64   = lambda data : u64(data.ljust(8,b'\x00'))


def to_bytes(x: Union[int, str, bytes]):
    """
    如果是int 就转成字符串再转成bytes
    如果是str 就直接.encode('latin-1') 转成bytes
    """
    if isinstance(x, int):
        return str(x).encode()
        # return x.to_bytes(loader.size//8, 'little')
    elif isinstance(x, str):
        return x.encode('latin-1')
    else:
        return x


def leak() -> int: 
    """
    leak libc address
    """
    ru = loader.io.recvuntil
    uu32 = lambda data : u32(data.ljust(4,b'\x00'))
    uu64 = lambda data : u64(data.ljust(8,b'\x00'))
    if loader.size == 32:
        return uu32(ru(b"\xf7")[-4:])   
    else:
        return uu64(ru(b"\x7f")[-6:])

def attach():
    gdb.attach(io)
    pause()

import ctypes as c
from . import (
    qemu,
    heap,
    exp,
    utils,
)
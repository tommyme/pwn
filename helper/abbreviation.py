from pwn import u32, u64, pause, success, info, context
import os
from helper import loader
# from pwn import
def abbre(glb,io,loader):
    """
    rl shell ru sl s bt psize sa sla
    """
    glb["rl"]       = io.recvline
    glb["r"]        = io.recv
    glb["shell"]    = io.interactive
    glb["ru"]       = lambda x : io.recvuntil(x)
    glb["sl"]       = lambda x : io.sendline(x)
    glb["s"]        = lambda x : io.send(x)
    glb["px"]    = lambda x : loader.psize(x)
    glb["sa"]       = lambda x, y : io.sendafter(x, y)
    glb["sla"]      = lambda x, y : io.sendlineafter(x, y)
    glb['uu32']     = lambda data : u32(data.ljust(4,b'\x00'))
    glb['uu64']     = lambda data : u64(data.ljust(8,b'\x00'))
    def f(info=""): success(f"{info}:{io.pid}"); a = os.system(f"echo 'attach {io.pid}' > .gdbinit"); pause(); 
    glb['pause']   = f
    glb['known_sym'] = lambda x : success(f"{x}: {hex(glb['libc'].sym[x])}")

# r = loader.io.recv
# rl = loader.io.recvline
# shell = loader.io.interactive
# ru = loader.io.recvuntil
# sl = loader.io.sendline
# s = loader.io.send
# sa = loader.io.sendafter
# sla = loader.io.sendlineafter
# px = loader.psize
# uu32 = lambda data : u32(data.ljust(4,b'\x00'))
# uu64 = lambda data : u64(data.ljust(8,b'\x00'))

bt = lambda x : bytes(str(x),encoding='utf-8') if type(x) != bytes else x

# def pause():
#     success(f"{info}:{loader.io.pid}") 
#     os.system(f"echo 'attach {loader.io.pid}' > .gdbinit")
#     pause(); 

def success_hex(addr:int, msg=""):
    success(f"{msg}: {hex(addr)}")

def info_hex(addr:int, msg=""):
    info(f"{msg}: {hex(addr)}")

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
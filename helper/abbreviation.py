from pwn import u32, u64, pause, success, info
import os
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
    glb["psize"]    = lambda x : loader.psize(x)
    glb["sa"]       = lambda x, y : io.sendafter(x, y)
    glb["sla"]      = lambda x, y : io.sendlineafter(x, y)
    glb['uu32']     = lambda data : u32(data.ljust(4,b'\x00'))
    glb['uu64']     = lambda data : u64(data.ljust(8,b'\x00'))
    def f(info=""): success(f"{info}:{io.pid}"); a = os.system(f"echo 'attach {io.pid}' > .gdbinit"); pause(); 
    glb['pause']   = f
    glb['known_sym'] = lambda x : success(f"{x}: {hex(glb['libc'].sym[x])}")


bt = lambda x : bytes(str(x),encoding='utf-8') if type(x) != bytes else x

def success_hex(addr:int, msg=""):
    success(f"{msg}: {hex(addr)}")

def info_hex(addr:int, msg=""):
    info(f"{msg}: {hex(addr)}")


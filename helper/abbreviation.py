from pwn import u32, u64, pause, success
import os
def abbre(glb,io,loader):
    """
    rl shell ru sl s bt psize sa sla
    """
    glb["rl"]       = io.recvline
    glb["shell"]    = io.interactive
    glb["ru"]       = lambda x : io.recvuntil(x)
    glb["sl"]       = lambda x : io.sendline(x)
    glb["s"]        = lambda x : io.send(x)
    glb["bt"]       = lambda x : bytes(str(x),encoding='utf-8') if type(x) != bytes else x
    glb["psize"]    = lambda x, y : loader.psize(x)
    glb["sa"]       = lambda x, y : io.sendafter(x, y)
    glb["sla"]      = lambda x, y : io.sendlineafter(x, y)
    glb['uu32']     = lambda data : u32(data.ljust(4,b'\x00'))
    glb['uu64']     = lambda data : u64(data.ljust(8,b'\x00'))
    def f(): success(str(io.pid)); a = os.system(f"echo 'attach {io.pid}' | clip.exe"); pause(); 
    glb['pause']   = f
    glb['known_sym'] = lambda x : success(f"{x}: {hex(glb['libc'].sym[x])}")
    # for heap
    

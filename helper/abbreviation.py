def abbre(glb,io,loader):
    """
    rl shell ru sl s bt psize sa sla
    """
    glb["rl"]       = io.recvline
    glb["shell"]    = io.interactive
    glb["ru"]       = lambda x : io.recvuntil(x)
    glb["sl"]       = lambda x : io.sendline(x)
    glb["s"]        = lambda x : io.send(x)
    glb["bt"]       = lambda x : bytes(str(x),encoding='utf-8')
    glb["psize"]    = lambda x, y : loader.psize(x)
    glb["sa"]       = lambda x, y : io.sendafter(x, y)
    glb["sla"]      = lambda x, y : io.sendlineafter(x, y)

    # for heap
    

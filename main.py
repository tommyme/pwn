from pwn import *
from LibcSearcher import *
from utils import log,show_ida_patch,nan
from loader import Loader
from pwnlib.util.proc import wait_for_debugger
from struct import pack
from qwq import *
import os
loader = Loader("target/easy_pwn", 64, patch=True)
elf = loader.elf
io = loader.process()
# io = loader.remote(25545)
# loader.debug()


log = nan
if 1:
    @log
    def ru(x): return io.recvuntil(x)
    @log
    def rl(): return io.recvline()
    @log
    def sla(x, y): return io.sendlineafter(x, y)
    @log
    def sl(x): return io.sendline(x)
    @log
    def s(x): return io.send(x)
    @log
    def sa(x, y): return io.sendafter(x, y)
    def psize(x): return loader.psize(x)
    def shell(): io.interactive()
    def bt(s): return bytes(str(s),encoding='utf-8')



def main():
    pass
    
    
    
if __name__ == "__main__":
    main()
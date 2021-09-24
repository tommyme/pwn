from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
import os
# from LibcSearcher import *
from helper.mbuiltins import *
from helper.utils import log,show_ida_patch,nan
from helper.loader import Loader

loader = Loader("target/magicheap", 64, patch=True)
elf = loader.elf
# io = loader.process()
io = loader.remote(26914)
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


def add(size,content):
    sla(b'choice :',b'1')
    sla(b'Size of Heap : ',bt(size))
    sla(b'Content of heap:',content)

def edit(id,size,content):
    sla(b'choice :',b'2')
    sla(b'Index :',bt(id))
    sla(b'Size of Heap : ',bt(size))
    sla(b'Content of heap : ',content)

def free(id):
    sla(b'choice :',b'3')
    sla(b'Index :',bt(id))

def show(id):
    sla(b'choice :',b'3')
    sla(b'Index :',bt(id))
    
def main():
    pass

    
    
if __name__ == "__main__":
    main()

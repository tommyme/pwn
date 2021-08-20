from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger

class Loader:
    def __init__(self,root,size):
        self.root = root
        self.size = size
        self.arch = 'amd64' if size == 64 else 'i386'
        context(arch=self.arch,os='linux')
        self.elf = ELF(self.root)

    def debug(self):
        context.log_level = 'debug'

    def remote(self,port):
        return remote('node4.buuoj.cn', port)

    def process(self):
        return process(self.root)

    def psize(self,x):
        return p32(x) if self.arch =='i386' else p64(x)

    def show_ida_patch_code(self,payload,st_addr):
        payload = ba.hexlify(payload).decode()
        step = 4 if self.arch =='i386' else 8
        func = "patch_dword" if self.arch =='i386' else "patch_qword"
        size = step * 2
        rg = len(payload)//size
        rg = rg+1 if len(payload)%size != 0 else rg
        for i in range(rg):
            a = payload[i*size:(i+1)*size]
            a = ''.join([a[2*j:2*(j+1)] for j in range(step)][::-1])
            print("ida_bytes.{}({},0x{})".format(func,hex(st_addr),a))
            st_addr += step

    def ROPgadget(self):
        print('ROPgadget --binary {} | grep "ret"'.format(self.root))
        print('ROPgadget --binary {} | grep "pop rdi ; ret"'.format(self.root))

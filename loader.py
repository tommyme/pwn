from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger
import os

class Loader:
    def __init__(self,root,size):
        self.root = root
        self.size = size
        self.arch = 'amd64' if size == 64 else 'i386'
        context(arch=self.arch,os='linux')
        self.elf = ELF(self.root)
        self.old_glibc_root = f'~/repos_pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_{self.arch}'

        self.old_glibc_pwnfile = pwnfile = [
            self.old_glibc_root+'/ld-2.23.so',
            '--library-path',
            self.old_glibc_root,
            self.root
        ]

    def debug(self):
        context.log_level = 'debug'

    def remote(self,port):
        return remote('node4.buuoj.cn', port)

    def process(self,old_glibc=False):
        if old_glibc:
            return process(self.old_glibc_pwnfile)
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

    def patchElf(self,buu=False):
        ogr = self.old_glibc_root
        num = '32' if self.arch == 'i386' else '64'
        buu_libc = f'~/repos_pwn/buuctf/16/{num}'
        print(buu_libc)
        if buu:
            cmd = f"patchelf --set-interpreter {ogr}/ld-2.23.so --set-rpath {buu_libc} {self.root}"
        else:
            cmd = f"patchelf --set-interpreter {ogr}/ld-2.23.so --set-rpath {ogr} {self.root}"

        os.system(cmd)

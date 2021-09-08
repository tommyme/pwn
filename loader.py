from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger
import os

class Loader:
    def __init__(self,root,size,patch=False):
        self.root = root
        self.size = size
        self.arch = 'amd64' if size == 64 else 'i386'
        context(arch=self.arch,os='linux')

        self.glibc_16_local = f'~/repos_pwn/glibc-all-in-one/libs/2.23-0ubuntu11.3_{self.arch}'
        self.glibc_16_pwnfile = [
            self.glibc_16_local+'/ld-2.23.so',
            '--library-path',
            self.glibc_16_local,
            self.root
        ]
        if patch:
            """
            本地的时候先用glibc_AIO来patch
            本地跑libcSearcher直接选glibc_AIO
            然后线上的时候libcSearcher直接选buuoj
            """
            self.patchElf()
        self.elf = ELF(self.root)

    def debug(self):
        context.log_level = 'debug'

    def remote(self,port):
        return remote('node4.buuoj.cn', port)

    def psize(self,x):
        return p32(x) if self.arch =='i386' else p64(x)

    def process(self):
        # if old_glibc:
            # return process(self.glibc_16_pwnfile)
        return process(self.root)


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

    # def ROPgadget(self):
    #     print('ROPgadget --binary {} | grep "ret"'.format(self.root))
    #     print('ROPgadget --binary {} | grep "pop rdi ; ret"'.format(self.root))

    def patchElf(self,buu=False):
        ogr = self.glibc_16_local
        num = '32' if self.arch == 'i386' else '64'
        buu_libc = f'~/pwn/buuctf/16/{num}'
        print(buu_libc)
        if buu:
            cmd = f"patchelf --set-interpreter {ogr}/ld-2.23.so --set-rpath {buu_libc} {self.root}"
        else:
            cmd = f"patchelf --set-interpreter {ogr}/ld-2.23.so --set-rpath {ogr} {self.root}"

        os.system(cmd)

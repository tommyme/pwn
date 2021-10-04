from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger
import os
j = os.path.join

class Loader:
    def __init__(self,root,size,debug=False):
        self.root = root
        self.size = size
        self.arch = 'amd64' if size == 64 else 'i386'
        context(arch=self.arch,os='linux')
        self.elf = ELF(self.root)
        self.libc = self.elf.libc
        if debug:
            context.log_level = 'debug'

    def remote(self,site='node4.buuoj.cn',port=0):
        return remote(site, port)

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


    def patch(self,ver:float,libc="",buu=False):
        """
        题目中给了libc就指定libc的路径
        要是在buu上面做题就用buu官方的libc
        要是都没给，也可以patch glibcAIO里面的libc
        ld都是通用的，但是题目里面通常不会给，这里统一采用glibcAIO里面的ld
        """
        if libc and buu:
            warning("不能同时选定buu和自己的libc！")
            exit()
        
        root = "/home/ybw/repos_pwn/glibc-all-in-one/libs"
        glibc = [i for i in os.listdir(root) if str(ver) in i and self.arch in i][0]
        self.glibc = j(root,glibc)
        self.glibc_ld = self.glibc+f'/ld-{ver}.so'
        self.glibc_16_pwnfile = [
            self.glibc_ld,
            '--library-path',
            self.glibc,
            self.root
        ]
        num = '32' if self.arch == 'i386' else '64'
        ubt = {'2.23':'16',"2.27":"18"}[str(ver)]
        buu_libc = f'~/pwn/buuctf/{ubt}/{num}'

        if buu:
            path = buu_libc
        elif libc:
            os.system(f"cp {libc} ./libc/libc.so.6")
            path = "~/pwn/temp_libc"
        else:
            path = self.glibc
        cmd = f"patchelf --set-interpreter {self.glibc_ld} --set-rpath {path} {self.root}"
        info(f"patch_cmd: {cmd}")
        os.system(cmd)

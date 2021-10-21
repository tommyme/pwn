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
        if debug:
            context.log_level = 'debug'
    def init(self):
        self.elf = ELF(self.root)
        self.libc = self.elf.libc
        return self.elf, self.libc

    def process(self,site='node4.buuoj.cn',port=0):
        if port:
            return remote(site, port)
        return process(self.root)
        

    def psize(self,x):
        return p32(x) if self.arch =='i386' else p64(x)

    def ida(self):
        v = "" if self.arch == "i386" else "64"
        io = process(f"server/linux_server{v}")
        io.recvuntil(b"...")
        io.recvuntil(b"...")
        return io

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


    def patch_AIO(self,ver:float,num=-1):
        """
        题目中给的libc一般是glibcAIO里面的一种, 
            buuoj里面ubt18的`glibc`就是AIO的`ubt1-2.27`
        ld相同版本可以混用

        args:
        - ver: libc version
        - num: sub version(eg: 2.27-3ubuntu`1.2`_amd64)
        """        
        info("""
        buu18 libc 对应 AIO 2.27-1
        buu16 没有对应
        """)
        root = j(os.getenv("HOME"),"repos_pwn/glibc-all-in-one/libs")
        default_num = {2.23:11.3,2.27:1,2.31:9.2}
        num = default_num[ver] if num < 0 else num
        glibc = [i for i in os.listdir(root) if str(ver) in i and f"ubuntu{num}_{self.arch}" in i][0]
        success(f"going to patch {glibc}...")
        self.glibc = j(root,glibc)
        self.glibc_ld = self.glibc+f'/ld-{ver}.so'
        self.glibc_16_pwnfile = [
            self.glibc_ld,
            '--library-path',
            self.glibc,
            self.root
        ]
        num = '32' if self.arch == 'i386' else '64'
        cmd = f"patchelf --set-interpreter {self.glibc_ld} --set-rpath {self.glibc} {self.root}"
        info(f"patch_cmd: {cmd}")
        os.system(cmd)

    def patch(self):
        # specify your own libc & specify buuoj libc
        pass

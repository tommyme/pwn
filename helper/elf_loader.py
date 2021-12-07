from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger
import os
import subprocess
import re
from collections import defaultdict, OrderedDict
from config import target

j = os.path.join
is_32bit = lambda path: len(os.popen(f"file {path} | grep 32-bit").read()) > 0
rwx = lambda path: os.system(f"chmod a+rwx {path}")
class Loader:
    def __init__(self,args):
        self.root = j(".target",target)
        self.size = 32 if is_32bit(self.root) else 64
        self.arch = 'amd64' if self.size == 64 else 'i386'
        success(f"loading {self.size}-bit {self.arch}")
        self.maps = {}
        self.section = {}
        self.pid = None
        self.io = None
        self.args = args
        context(arch=self.arch,os='linux')
        if args.debug:
            context.log_level = 'debug'

    def init(self):
        self.elf = ELF(self.root)
        self.libc = self.elf.libc
        self.rop = ROP(self.root)
        return self.elf, self.libc, self.rop

    def process(self, site='node4.buuoj.cn'):
        rwx(self.root)
        if self.args.port:
            io = remote(site, self.args.port)
        elif self.args.ida:
            v = "" if self.arch == "i386" else "64"
            io = process(f".server/linux_server{v}")
            io.recvuntil(b"...")
            io.recvuntil(b"...")
        else:
            io = process(self.root)
            self.pid = io.pid
        self.io = io
        return io

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

    def patch_AIO(self,ver:float,dir="",num=-1):
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
        self.glibc = dir if dir else self.glibc
        cmd = f"patchelf --set-interpreter {self.glibc_ld} --set-rpath {self.glibc} {self.root}"
        info(f"patch_cmd: {cmd}")
        os.system(cmd)

    def patch(self):
        # specify your own libc & specify buuoj libc
        pass
    
    def update(self, *args, **kwargs):
        for arg in args:
            self.update(**arg)

        for k,v in kwargs.items():
            setattr(self,k,v)
        
    def get_addrs(self, filename:str=None) -> dict:
        """
        Read /proc/pid/maps file to get base address. Return a dictionary obtaining keys: 'code',
        'libc', 'ld', 'stack', 'heap', 'vdso'.

        Returns:
            dict: All segment address. Key: str, Val: int.
        """
        
        assert isinstance(self.pid, int), "error type!"
        res = None
        try:
            res = subprocess.check_output(["cat", f"/proc/{self.pid}/maps"]).decode().split("\n")
        except:
            error(f"cat /proc/{self.pid}/maps failed!")
        _d = defaultdict(int,{})
        code_flag = 0
        libc_flag = 0
        ld_flag = 0

        for r in res:
            rc = re.compile(r"^([0123456789abcdef]{6,14})-([0123456789abcdef]{6,14})", re.S)
            rc = rc.findall(r)
            if len(rc) != 1 or len(rc[0]) != 2:
                continue
            start_addr = int(rc[0][0], base=16)
            end_addr = int(rc[0][1], base=16)

            if  (not _d['code']) and self.root in r:
                _d['code'] = start_addr
            elif (not libc_flag) and ("/libc-2." in r or "/libc.so" in r):
                libc_flag = 1
                _d['libc'] = start_addr
            elif (not ld_flag) and ("/ld-2." in r):
                ld_flag = 1
                _d['ld'] = start_addr
            elif "heap" in r:
                _d['heap'] = start_addr
            elif "stack" in r:
                _d['stack'] = start_addr  
            elif "vdso" in r:
                _d['vdso'] = start_addr
        self.maps.update(_d)

        try:
            res = subprocess.check_output(["readelf", "-S", self.root]).decode().split("\n")
        except:
            error(f"readelf -S {self.root} failed!")
        
        for line in res:
            matched = re.findall(r"\.[a-z\.]+",line)
            if matched:
                addr, offset = re.findall(r"[\da-f]{3,}",line)
                addr = int(addr, 16)
                self.section[matched[0]] = addr+self.maps["code"]

    def buulibc(self,v,arch):
        return ELF(f".buuoj/{v}/{arch}/libc.so.6")
    
    def get_og(self, path=""):
        path = path if path else self.libc.path
        cmd = os.popen(f"one_gadget {path} | grep execve | awk -F\" \" '{{print $1}}'")
        res = cmd.read().strip().split('\n')
        success(f"og = [{','.join(res)}]")
from pwn import *
import binascii as ba
from pwnlib.util.proc import wait_for_debugger
import os
import subprocess
import re
from collections import defaultdict, OrderedDict
from helper.config import pickle_cache, target_binary

j = os.path.join
def rwx(path): return os.system(f"chmod a+rwx {path}")


class Loader:
    def __init__(self, args):
        self.root = target_binary.path
        self.size = target_binary.bit
        self.arch = target_binary.arch
        success(f"loading {self.size}-bit {self.arch}")
        self.maps = {}
        self.section = {}
        self.pid = None
        self.io = None
        self.args = args
        context(arch=self.arch, os='linux')
        if args.debug:
            context.log_level = 'debug'

    def init(self):
        """
        LOCAL MODE: 
            get elf, libc, rop of binary
        REMOTE MODE:
            get elf, libc(buuoj), rop of binary
        """
        self.patch(self.args.patch) if self.args.patch else 0
        self.elf = ELF(self.root)
        # TODO: there is some question: ideally, we want patch libc into buu_libc
        #   in order to keep one gadgets are the same in local and remote
        #   the way to achieve that is:
        #       resolve the path of libc in buuoj and pass it to self.patch()
        self.libc = self.buulibc(
            self.args.buu, self.size) if self.args.buu else self.elf.libc
        self.rop = ROP(self.root)
        self.get_og() if self.args.og else 0

        return self.elf, self.libc, self.rop

    def process(self):
        # use buuoj as host by default
        site = args.host if args.host else 'node4.buuoj.cn'
        rwx(self.root)
        # when specify port, will pwn remote
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

    def psize(self, x):
        return p32(x) if self.arch == 'i386' else p64(x)

    def show_ida_patch_code(self, payload, st_addr):
        payload = ba.hexlify(payload).decode()
        step = 4 if self.arch == 'i386' else 8
        func = "patch_dword" if self.arch == 'i386' else "patch_qword"
        size = step * 2
        rg = len(payload)//size
        rg = rg+1 if len(payload) % size != 0 else rg
        for i in range(rg):
            a = payload[i*size:(i+1)*size]
            a = ''.join([a[2*j:2*(j+1)] for j in range(step)][::-1])
            print("ida_bytes.{}({},0x{})".format(func, hex(st_addr), a))
            st_addr += step

    def patch(self, ver: float, libc_path=""):
        """
        buuoj ubt18 glibc -- AIO ubt1-2.27
        ld相同版本可以混用

        args:
        - ver: libc version
        - libc_path: libc path(not in glibc_all_in_one)
        """
        # sync with tools/patch.py
        def patch_AIO(arch, binary_path, ver:float, libc_path=""):
            """
            args:
            - arch: i386 or amd64
            - root: binary path
            - ver: libc version
            - libc_path: libc path(not in glibc_all_in_one)
            """        

            aio_root = j(os.getenv("HOME"),"repos_pwn/glibc-all-in-one/libs")
            glibc_list = [i for i in os.listdir(aio_root) if str(ver) in i and f"{arch}" in i]
            if not glibc_list: 
                error(
                    f"no glibc found for {ver} " \
                    "please download it in glibc-aio"
                )
            info("idx of glibc to patch:(default is 0)\n{}".format('\n'.join(glibc_list)))
            char = input()
            idx = int(char) if char.isdigit() else 0
            success(f"going to patch {glibc_list[idx]}...")
            
            # generate info and command
            glibc = j(aio_root, glibc_list[idx]) if not libc_path else libc_path
            glibc_ld = glibc+f'/ld-{ver}.so'
            # provide a way of patching when running 
            glibc_16_pwnfile = [
                glibc_ld,
                '--library-path',
                glibc,
                binary_path
            ]
            cmd = ["patchelf", f"--set-interpreter {glibc_ld}", f"--set-rpath {glibc}", f"{binary_path}"]
            cmd_formatted = ' \\ \n'.join(cmd)
            info(f"patch_cmd: {cmd_formatted}")
            os.system(' '.join(cmd))

            return glibc, glibc_ld, glibc_16_pwnfile

        self.glibc, self.glibc_ld, self.glibc_16_pwnfile = \
            patch_AIO(self.arch, self.root, ver, libc_path)

    def update(self, *args, **kwargs):
        for arg in args:
            self.update(**arg)

        for k, v in kwargs.items():
            setattr(self, k, v)

    def get_addrs(self, filename: str = None) -> dict:
        """
        Read /proc/pid/maps file to get base address. Return a dictionary obtaining keys: 'code',
        'libc', 'ld', 'stack', 'heap', 'vdso'.

        Returns:
            dict: All segment address. Key: str, Val: int.
        """

        assert isinstance(self.pid, int), "error type!"
        res = None
        try:
            res = subprocess.check_output(
                ["cat", f"/proc/{self.pid}/maps"]).decode().split("\n")
        except:
            error(f"cat /proc/{self.pid}/maps failed!")
        _d = defaultdict(int, {})
        code_flag = 0
        libc_flag = 0
        ld_flag = 0

        for r in res:
            rc = re.compile(
                r"^([0123456789abcdef]{6,14})-([0123456789abcdef]{6,14})", re.S)
            rc = rc.findall(r)
            if len(rc) != 1 or len(rc[0]) != 2:
                continue
            start_addr = int(rc[0][0], base=16)
            end_addr = int(rc[0][1], base=16)

            if (not _d['code']) and self.root in r:
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
            res = subprocess.check_output(
                ["readelf", "-S", self.root]).decode().split("\n")
        except:
            error(f"readelf -S {self.root} failed!")

        for line in res:
            matched = re.findall(r"\.[a-z\.]+", line)
            if matched:
                addr, offset = re.findall(r"[\da-f]{3,}", line)
                addr = int(addr, 16)
                self.section[matched[0]] = addr+self.maps["code"]

    def buulibc(self, v:int, bit:int):
        return ELF(f".buuoj/{v}_{bit}_libc.so.6")

    def get_og(self, path=""):
        """
        get one gadget
        """
        import pickle
        path = path if path else self.libc.path
        if os.path.exists(pickle_cache):
            with open(pickle_cache, "rb") as f:
                cache = pickle.load(f)
                if cache['path'] == path:
                    info("detect one gadget cached.")
                    return
        cmd = os.popen(
            f"one_gadget {path} | grep execve | awk -F\" \" '{{print $1}}'")
        res = cmd.read().strip().split('\n')
        success(f"og = [{','.join(res)}], writing -> {pickle_cache} ...")
        with open(pickle_cache, "wb") as f:
            pickle.dump({
                "path": self.libc.path,
                "og": [int(i, 16) for i in res]
            }, f)

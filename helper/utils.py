from functools import wraps
import binascii as ba
from pwn import info
import os

def easy_libc(libc, key="", value=0, addr=0):
    from helper.config import pickle_cache
    if key and value:
        libc.address = value - libc.sym[key]
    elif addr:
        libc.address = addr
    info(f"[easy_libc] libc base: {hex(libc.address)}")
    libc.__dict__.update(libc.sym)
    if os.path.exists(pickle_cache):
        data = get_pickle_content(pickle_cache)
        data['og'] = [libc.address+i for i in data['og']]
        setattr(libc, "one_gadget", data['og'])

def get_pickle_content(path):
    import pickle
    with open(path,"rb") as f:
        content = pickle.load(f)
    return content

class Binary:
    def __init__(self, path):
        self.path = path
        self.bit: int = 32 if self.is_32bit() else 64
        self.arch: str = "i386" if self.bit == 32 else "amd64"
    
    def is_32bit(self): 
        return len(os.popen(f"file {self.path} | grep 32-bit").read()) > 0

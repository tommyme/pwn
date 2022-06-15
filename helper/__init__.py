from helper.mbuiltins import *
from helper.elf_loader import Loader
from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
import os
from .arg import args


context.terminal = ['cmd.exe', '/c', 'wt', '-w', '0', 'sp', 'wsl', '-e']

loader = Loader(args)
elf,libc,rop = loader.init()
io = loader.process()
import ctypes as c
from helper.abbreviation import *
from . import (
    qemu,
    heap,
    exp,
    utils,
)
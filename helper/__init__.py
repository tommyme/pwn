from helper.mbuiltins import *
from helper.utils import log,show_ida_patch,nan
from helper.elf_loader import Loader

from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
import os
from .arg import args

loader = Loader(args)
elf,libc,rop = loader.init()
io = loader.process()

from helper.abbreviation import *
from . import (
    qemu,
    heap,
    exp,
)
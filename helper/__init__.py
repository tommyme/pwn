from helper.mbuiltins import *
from helper.utils import log,show_ida_patch,nan
from helper.loader import Loader
from helper.abbreviation import (
    abbre,
    bt,
    success_hex,
    info_hex,
)
from helper.heap import menu, heap_helper

from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
import os
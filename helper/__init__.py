from helper.mbuiltins import *
from helper.utils import log,show_ida_patch,nan
from helper.loader import Loader
from helper.abbreviation import abbre
from helper.heap import menu

from pwn import *
from pwnlib.util.proc import wait_for_debugger
from struct import pack
import os
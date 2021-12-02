# from LibcSearcher import *
from helper import *
import helper
from pwncli import *
import ctypes as c
from struct import pack

loader = Loader(".target/axb_2019_fmt64", 32, debug=True)
loader.patch_AIO(2.27)
elf,libc,rop = loader.init()
io = loader.process(parser.parse_args())
abbre(globals(), io, loader) # 此处定义了常用的缩写
# loader.get_addrs()


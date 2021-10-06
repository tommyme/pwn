# from LibcSearcher import *
from helper import *
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/hahapwn", 64, debug=False)
loader.patch(2.23)
loader.init()
elf,libc = loader.elf, loader.libc
# libc = ELF("libc.so.6")
io = loader.process()
# io = loader.remote(port=27114)
abbre(globals(), io, loader) # 此处定义了常用的缩写
# menu(globals())
# wait_for_debugger(io.pid)
# your code here

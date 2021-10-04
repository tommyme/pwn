# from LibcSearcher import *
from helper import *
from exp import ret2libc_A, ret2libc_B
loader = Loader("target/datasystem", 64, debug=False)
loader.patch(2.27)
elf,libc = loader.elf, loader.libc
# libc = ELF("")
io = loader.process()
# io = loader.remote(port=26914)
abbre(globals(), io, loader) # 此处定义了常用的缩写
menu(globals())



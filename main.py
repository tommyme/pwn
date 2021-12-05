from helper import *
import helper

loader = Loader(debug=True)
elf,libc,rop = loader.init()
io = loader.process(parser.parse_args())
abbre(globals(), io, loader) # 此处定义了常用的缩写
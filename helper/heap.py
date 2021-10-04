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

    tips = b">> :\n"
    
    def add(size, data=b"aaaa"):
        sla(tips, b"1")
        sla(b"Size: \n", bt(size))
        sa(b"what's your Content: \n", data)

    def free(idx):
        sla(tips, b"2")
        sla(b"Index:\n", bt(idx))

    def show(idx):
        sla(tips, b"3")
        sla(b"Index:\n", bt(idx))

    def edit(idx, data):
        sla(tips, b"4")
        sla(b"Index:\n", bt(idx))
        sa(b"Content:\n", data) 

    glb['add'] = add
    glb['free'] = free
    glb['show'] = show
    glb['edit'] = edit
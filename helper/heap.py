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
    
    def add(size,payload):
        sla(b'choice :',b'1')
        sla(b'size :',bt(size))
        sla(b'Content :',payload)

    def free(idx):
        sla(b'choice :',b'4')
        sla(b'Index :',bt(idx))

    def edit(idx,size,content):
        sla(b'choice :',b'3')
        sla(b'Index :',bt(idx))
        sla(b'Size: ',bt(size))
        sla(b'Content: ',content)

    def show(id):
        sla(b'choice',b"2")
        sla(b'Index',bt(id))

    glb['add'] = add
    glb['free'] = free
    glb['show'] = show
    glb['edit'] = edit
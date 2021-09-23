import angr
import claripy

p=angr.Project('target/funnyre',load_options={"auto_load_libs": False})
f=p.factory
state = f.entry_state(addr=0x400605)
flag = claripy.BVS('flag',8*32)#用BVS转成二进制给
state.memory.store(0x603055+0x300+5,flag)#因为程序没有输入，所以直接把字符串设置到内存
state.regs.rdx=0x603055+0x300
state.regs.rdi=0x603055+0x300+5#然后设置两个寄存器

sm = p.factory.simulation_manager(state)#准备从state开始遍历路径


print("get start!")

sm.explore(find=0x401DAE)#遍历到成功的地址

if sm.found:
    print("success")
    x=sm.found[0].solver.eval(flag,cast_to=bytes)
    print(x)
else:
    print('yenkoc')

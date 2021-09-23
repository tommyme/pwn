#!/usr/bin/python
# -*- coding: UTF-8 -*-
import angr
import time


path = '01_angr_avoid'
start = time.time()

p = angr.Project(path)
init_st = p.factory.entry_state()
sm = p.factory.simulation_manager(init_st)


def want(st):
    return b'Good Job' in st.posix.dumps(1)


def not_want(st):
    return b'Try again' in st.posix.dumps(1)
    # return


sm.explore(find=0x080485E0, avoid=0x080485F2)  # 加入avoid 更快

if sm.found:
    fs_st = sm.found[0]
    key = fs_st.posix.dumps(0)  # dumps() 传0表示输入 传1表示输出
    print('key is {}'.format(key))
else:
    print('key not found')
print('用时', int(time.time()-start), 's')
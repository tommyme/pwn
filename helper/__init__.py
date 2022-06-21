from pwn import *
import ctypes as c
context.terminal = ['wt.exe', '-w', '0', 'sp', 'wsl', '-e']

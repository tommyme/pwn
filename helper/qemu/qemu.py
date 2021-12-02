from pwnlib.tubes.process import process

def dump_remote_qemu_img(io: process, path):
    """
    当远程qemu没有开monitor重定向的情况下可以dump img
    make sure you have enter the `qemu-monitor`
    """
    # qemu 挂起
    io.sendlineafter(b"(qemu)",b"stop")
    # qemu add block from remote
    io.sendlineafter(b'(qemu)', f'drive_add 0 file={path},id=flag,format=raw,if=none,readonly=on')
    # 
    pass
    
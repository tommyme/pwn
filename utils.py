from functools import wraps
import binascii as ba


def trans(s):
    if s.startswith('0x'):
        s = s[2:]
    s = s.rjust(size//4, '0')
    res = []
    for i in range(len(s)//2):
        res.append(s[2*i:2*i+2])

    return " ".join(res[::-1])


def transs(ss):
    return ' '.join([trans(i) for i in ss])


def show_ida_patch(payload, pos):
    print("\nshow_ida_patch : ")
    print(pos*'a'+(len(payload)-pos)*'*')
    res = ' '.join(["%02x" % i if id % (size//4) !=
          0 else "| %02x" % i for id, i in enumerate(payload[pos:])])
    [print(i.strip()) for i in res.split('|')]


def log(a_func):
    @wraps(a_func)
    def decorator(*args):
        res = a_func(*args)
        print("{}: {}".format(a_func.__name__,res))
    return decorator


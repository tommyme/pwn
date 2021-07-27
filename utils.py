def trans(s, size=64):
    if s.startswith('0x'):
        s = s[2:]
    s = s.rjust(size//4, '0')
    res = []
    for i in range(len(s)//2):
        res.append(s[2*i:2*i+2])

    return " ".join(res[::-1])


def transs(ss, size=64):
    return ' '.join([trans(i) for i in ss])


def show_ida_patch(payload, pos, size=64):
    print(pos*'a'+(len(payload)-pos)*'*')
    print(' '.join(["%02x" % i if id % (size//4) !=
          0 else "| %02x" % i for id, i in enumerate(payload[pos:])]))

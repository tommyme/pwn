from forbiddenfruit import curse


if 'str':
    def b(self):
        return bytes(str(self),encoding='utf-8')
    curse(str, "b", b)

    # def partition(self, size):
    #     return [self[i:i+size] for i in range(0, len(self), size)]
    # curse(str,'partition',partition)

if "int":
    def b(self):
        return bytes(str(self),encoding='utf-8')
    curse(int, "b", b)



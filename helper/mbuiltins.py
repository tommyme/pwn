from forbiddenfruit import curse
import ctypes

if 'str':
    def b(self):
        return bytes(str(self), encoding='utf-8')
    curse(str, "b", b)

    # def partition(self, size):
    #     return [self[i:i+size] for i in range(0, len(self), size)]
    # curse(str,'partition',partition)

if "int":
    def b(self):
        return bytes(str(self), encoding='utf-8')
    curse(int, "b", b)
    def retype(self,ctype):
        return getattr(ctypes,f"c_{ctype}")(self).value
    curse(int,"retype",retype)


class cint(int):
    def __new__(cls, value, ctype, *args, **kwargs):
        value = getattr(ctypes,f"c_{ctype}")(value).value        
        return  super(cls, cls).__new__(cls, value)

    def __init__(self,value,ctype):
        self.ctype = ctype
        value = getattr(ctypes,f"c_{ctype}")(value).value    
        int.__init__(value)

    def __add__(self, other):
        res = super(cint, self).__add__(other)
        return self.__class__(res,self.ctype)
    
    def __sub__(self, other):
        res = super(cint, self).__sub__(other)
        return self.__class__(res,self.ctype)
    # python中bin返回的是"-34 -0b 0010 0010"这种，但是计算机存储的是反码
    # 也就是说 -0b 1000 0010 等价于 0b 1101 1110 （取反加一）
    def __lshift__(self,n):
        res = super(cint,self).__lshift__(n)
        return self.__class__(res,self.ctype)

    def __rshift__(self,n):
        res = super(cint,self).__rshift__(n)
        return self.__class__(res,self.ctype)

# a = cint(222,'int8')
# print(a, bin(a))
# b = a << 2
# print(b, bin(b))






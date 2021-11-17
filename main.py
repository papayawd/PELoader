import struct
from binascii import *


class PE:
    def GetValue(self, offset, type='dword'):
        if(type == 'word'):
            return hexlify(self.FileBuff[offset:offset + 2])
        if type == 'dword':
            return hexlify(self.FileBuff[offset:offset + 4])

    def __init__(self, FileBuff):
        self.FileBuff = FileBuff
        self.e_magic = self.GetValue(offset=0,type='word')

    def info(self):
        print(type(self.e_magic))
        print('MZ标志位 {}'.format(self.e_magic))

with open('./Lab03-03.exe','rb+') as f:
    FileBuffer = f.read()
    #print(FileBuffer)
    PE(FileBuffer).info()
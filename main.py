import struct
from binascii import *


class IMAGE_THUNK_DATA32:

    def getvalue(self, offset, size='dword'):
        if size == 'byte':
            return int(hexlify(self.FileBuff[offset:offset + 1][::-1]), 16)

        if size == 'word':
            return int(hexlify(self.FileBuff[offset:offset + 2][::-1]), 16)

        if size == 'dword':
            return int(hexlify(self.FileBuff[offset:offset + 4:][::-1]), 16)

    def getstring(self, offset):
        s = ''
        while self.getvalue(offset=offset, size='byte') != 0:
            s += chr(self.getvalue(offset=offset, size='byte'))
            offset += 1
        return s

    def __init__(self, FileBuff, offset):
        self.FileBuff = FileBuff
        self.offset = offset
        self.Ordinal = self.getvalue(offset=self.offset)
        self.function = hex(self.getvalue(offset=self.offset))
        self.Name = ''
        if self.Ordinal & (1 << 31) == 0:
            self.Name = self.getstring(self.Ordinal + 0x2)


class IMAGE_IMPORT_DESCRIPTOR:

    def getvalue(self, offset, size='dword'):
        if size == 'byte':
            return int(hexlify(self.FileBuff[offset:offset + 1][::-1]), 16)

        if size == 'word':
            return int(hexlify(self.FileBuff[offset:offset + 2][::-1]), 16)

        if size == 'dword':
            return int(hexlify(self.FileBuff[offset:offset + 4:][::-1]), 16)

    def getstring(self, offset):
        s = ''
        while self.getvalue(offset=offset, size='byte') != 0:
            s += chr(self.getvalue(offset=offset, size='byte'))
            offset += 1
        return s

    def __init__(self, FileBuff, offset):
        self.FileBuff = FileBuff
        self.offset = offset
        self.OriginalFirstThunk = self.getvalue(offset=self.offset)
        self.TimeDateStamp = hex(self.getvalue(offset=self.offset + 0x4))
        self.Name = self.getstring(self.getvalue(offset=self.offset + 0xc))
        self.FirstThunk = self.getvalue(offset=self.offset + 0x10)


class IMAGE_DATA_DIRECTORY:

    def getvalue(self, offset, size='dword'):
        if size == 'byte':
            return int(hexlify(self.FileBuff[offset:offset + 1][::-1]), 16)

        if size == 'word':
            return int(hexlify(self.FileBuff[offset:offset + 2][::-1]), 16)

        if size == 'dword':
            return int(hexlify(self.FileBuff[offset:offset + 4:][::-1]), 16)

    def __init__(self, FileBuff, offset):
        self.FileBuff = FileBuff
        self.offset = offset
        self.VirtualAddress = self.getvalue(offset=self.offset)
        self.Size = self.getvalue(offset=self.offset + 0x4)


class IMAGE_SECTION_HEADER:

    def getvalue(self, offset, size='dword'):
        if size == 'byte':
            return int(hexlify(self.FileBuff[offset:offset + 1][::-1]), 16)

        if size == 'word':
            return int(hexlify(self.FileBuff[offset:offset + 2][::-1]), 16)

        if size == 'dword':
            return int(hexlify(self.FileBuff[offset:offset + 4:][::-1]), 16)

    def getstring(self, offset):
        s = ''
        cnt = 0
        while self.getvalue(offset=offset, size='byte') != 0:
            s += chr(self.getvalue(offset=offset, size='byte'))
            offset += 1
            if ++cnt == 8:  # 对section的name特殊判断一下 因为只有8字节供存储
                break
        return s

    def __init__(self, FileBuff, offset):
        self.FileBuff = FileBuff
        self.offset = offset
        self.Name = self.getstring(offset=self.offset)
        self.VirtualSize = hex(self.getvalue(offset=self.offset + 0x8))
        self.VirtualAddress = hex(self.getvalue(offset=self.offset + 0xc))
        self.SizeOfRawData = hex(self.getvalue(offset=self.offset + 0x10))
        self.PointerToRawData = hex(self.getvalue(offset=self.offset + 0x14))
        self.Characteristics = hex(self.getvalue(offset=self.offset + 0x24))


class PE:

    def getvalue(self, offset, size='dword'):
        if size == 'byte':
            return int(hexlify(self.FileBuff[offset:offset + 1][::-1]), 16)

        if size == 'word':
            return int(hexlify(self.FileBuff[offset:offset + 2][::-1]), 16)

        if size == 'dword':
            return int(hexlify(self.FileBuff[offset:offset + 4:][::-1]), 16)

    def __init__(self, FileBuff):

        # DOS头
        self.FileBuff = FileBuff
        self.e_magic = hex(self.getvalue(offset=0, size='word'))
        self.NT_header = self.getvalue(offset=0x3c)

        # PE头
        self.PE_Signature = hex(self.getvalue(offset=self.NT_header, size='word'))
        self.FileHeader = self.NT_header + 0x4
        self.NumberOfSections = self.getvalue(offset=self.FileHeader + 0x2, size='word')
        self.TimeDateStamp = hex(self.getvalue(offset=self.FileHeader + 0x4))
        self.SizeOfOptionalHeader = self.getvalue(offset=self.FileHeader + 0x10, size='word')

        # 可选PE头
        self.OP_Header = self.NT_header + 0x18
        self.Magic = hex(self.getvalue(offset=self.OP_Header, size='word'))  # 机器码
        self.SizeOfCode = hex(self.getvalue(offset=self.OP_Header + 0x4))  # 代码段大小
        self.AddressOfEntryPoint = hex(self.getvalue(offset=self.OP_Header + 0x10))
        self.BaseOfCode = hex(self.getvalue(offset=self.OP_Header + 0x14))  # 代码段偏移
        self.BaseOfData = hex(self.getvalue(offset=self.OP_Header + 0x18))  # 数据段偏移
        self.ImageBase = hex(self.getvalue(offset=self.OP_Header + 0x1c))
        self.SectionAlignment = hex(self.getvalue(offset=self.OP_Header + 0x20))  # 内存对齐
        self.FileAlignment = hex(self.getvalue(offset=self.OP_Header + 0x24))  # 文件对齐
        self.SizeOfImage = hex(self.getvalue(offset=self.OP_Header + 0x38))
        self.CheckSum = hex(self.getvalue(offset=self.OP_Header + 0x40))  # 校验和

        # 导出表
        self.IMAGE_DIRECTORY_ENTRY_EXPORT = IMAGE_DATA_DIRECTORY(FileBuff=self.FileBuff,
                                                                 offset=self.OP_Header + 0x60 + 0 * 0x8)
        # 导入表
        self.IMAGE_DIRECTORY_ENTRY_IMPORT = IMAGE_DATA_DIRECTORY(FileBuff=self.FileBuff,
                                                                 offset=self.OP_Header + 0x60 + 1 * 0x8)
        # IAT表
        self.IMAGE_DIRECTORY_ENTRY_IAT = IMAGE_DATA_DIRECTORY(FileBuff=self.FileBuff,
                                                              offset=self.OP_Header + 0x60 + 12 * 0x8)

        self.SectionBegin = self.NT_header + 0x18 + self.SizeOfOptionalHeader # DOS头+PE头+可选PE头

    def info(self):
        print(type(self.e_magic))
        print('*****************DOS头*********************')
        print('MZ标志位: {}'.format(self.e_magic))
        print('\n')

        print('*****************PE头*********************')
        print('==> PE文件头大小: {}'.format(hex(0x14)))
        print('PE标志位: {}'.format(self.PE_Signature))
        print('时间戳: {}'.format(self.TimeDateStamp))
        print('\n')

        print('*****************可选PE头*********************')
        print('==> 可选PE头大小: {}'.format(hex(self.SizeOfOptionalHeader)))
        print('魔数: {}'.format(self.Magic))
        print('程序入口点: {}'.format(self.AddressOfEntryPoint))
        print('代码段基地址: {}'.format(self.BaseOfCode))
        print('数据段基地址: {}'.format(self.BaseOfData))
        print('镜像基地址: {}'.format(self.ImageBase))
        print('文件对齐大小: {}'.format(self.FileAlignment))
        print('内存对齐大小: {}'.format(self.SectionAlignment))
        print('镜像文件大小: {}'.format(self.SizeOfImage))
        print('校验和: {}'.format(self.CheckSum))
        print('\n')

        print('*****************目录*********************')
        print('导出表: {}  大小: {}'.format(hex(self.IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress),
                                       hex(self.IMAGE_DIRECTORY_ENTRY_EXPORT.Size)))
        print('导入表: {}  大小: {}'.format(hex(self.IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress),
                                       hex(self.IMAGE_DIRECTORY_ENTRY_IMPORT.Size)))
        print('IAT表: {}  大小: {}'.format(hex(self.IMAGE_DIRECTORY_ENTRY_IAT.VirtualAddress),
                                        hex(self.IMAGE_DIRECTORY_ENTRY_IAT.Size)))

        print('*****************导出表*********************')
        ENTRY_IMPORT_OFFSET = self.IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress
        while IMAGE_IMPORT_DESCRIPTOR(self.FileBuff,
                                      ENTRY_IMPORT_OFFSET).OriginalFirstThunk != 0:
            DLL = IMAGE_IMPORT_DESCRIPTOR(self.FileBuff, self.IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress)
            ENTRY_IMPORT_OFFSET += 0x14
            print('模块名称: {}'.format(DLL.Name))
            print('\t时间戳: {}'.format(DLL.TimeDateStamp))
            print('\t导入函数名\t\t\t\t导入函数偏移')
            THUNK_OFFSET = DLL.OriginalFirstThunk
            FUNC_OFFSET = DLL.FirstThunk
            while IMAGE_THUNK_DATA32(self.FileBuff, THUNK_OFFSET).Ordinal != 0:
                thunk_name = IMAGE_THUNK_DATA32(self.FileBuff, THUNK_OFFSET)
                thunk_func = IMAGE_THUNK_DATA32(self.FileBuff, FUNC_OFFSET)
                print('\t{}\t\t\t\t{}'.format(thunk_name.Name, thunk_func.function))  ## 这里的对齐有点点丑  有空再来想办法改一改
                FUNC_OFFSET += 0x4
                THUNK_OFFSET += 0x4
            print('\n')
        print(hex(self.SectionBegin))
        print('*****************节区*********************')
        print('区段名称\t\t文件内大小\t\t文件内偏移\t\t对齐后大小\t\t对齐后偏移\t\t属性')
        SECTION_OFFSET = self.SectionBegin

        for i in range(self.NumberOfSections):
            section = IMAGE_SECTION_HEADER(self.FileBuff, SECTION_OFFSET)
            print('{}\t\t{}\t\t\t{}\t\t\t{}\t\t\t{}\t\t\t{}'.format(section.Name, section.VirtualSize, section.VirtualAddress,
                                                            section.SizeOfRawData, section.PointerToRawData,
                                                            section.Characteristics))

            SECTION_OFFSET += 0x28


if __name__ == '__main__':
    with open('./Lab03-03.exe', 'rb+') as f:
        FileBuff = f.read()
        # print(FileBuffer)
        lab = PE(FileBuff=FileBuff)
        print(type(lab))
        lab.info()

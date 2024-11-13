import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class IMAGE_FILE_HEADER:
    def __init__(self, data):
        self.Machine, \
        self.NumberOfSections, \
        self.TimeDateStamp, \
        self.PointerToSymbolTable, \
        self.NumberOfSymbols, \
        self.SizeOfOptionalHeader, \
        self.Characteristics \
            = struct.unpack('<HHIIIHH', data)

class IMAGE_SECTION_HEADER:
    def __init__(self, data):
        self.Name, \
        self.VirtualSize, \
        self.VirtualAddress, \
        self.SizeOfRawData, \
        self.PointerToRawData, \
        self.PointerToRelocations, \
        self.PointerToLinenumbers, \
        self.NumberOfRelocations, \
        self.NumberOfLinenumbers, \
        self.Characteristics \
            = struct.unpack('<8sIIIIIIHHI', data)

class IMAGE_RELOCATION:
    def __init__(self, data):
        self.VirtualAddress, \
        self.SymbolTableIndex, \
        self.Type, \
            = struct.unpack('<IIH', data)

class IMAGE_SYMBOL:
    def __init__(self, data):
        self.N, \
        self.Value, \
        self.SectionNumber, \
        self.Type, \
        self.StorageClass, \
        self.NumberOfAuxSymbols \
            = struct.unpack('<8sIHHBB', data)

def GetHash(bytes):
    hash = 0
    for byte in bytes:
        hash += byte
        hash = (hash << 8) - hash
    hash = (hash & 0xffffffff ^ 0x80000000) - 0x80000000
    return hash

def ParseBOF(bof):
    text = rdata = relocNum = relocOffset = None
    fileHeader = IMAGE_FILE_HEADER(bof[:struct.calcsize('<HHIIIHH')])
    for i in range(fileHeader.NumberOfSections):
        offset = struct.calcsize('<HHIIIHH') + i * struct.calcsize('<8sIIIIIIHHI')
        sectionHeader = IMAGE_SECTION_HEADER(bof[offset:offset+struct.calcsize('<8sIIIIIIHHI')])
        if sectionHeader.Name == b'.text\x00\x00\x00':
            relocNum = sectionHeader.NumberOfRelocations
            relocOffset = sectionHeader.PointerToRelocations
            text = bof[sectionHeader.PointerToRawData:sectionHeader.PointerToRawData+sectionHeader.SizeOfRawData]
        elif sectionHeader.Name == b'.rdata\x00\x00':
            rdata = bof[sectionHeader.PointerToRawData:sectionHeader.PointerToRawData+sectionHeader.SizeOfRawData]
    if text == None:
        raise Exception('Not found: .text')
    if rdata == None:
        raise Exception('Not found: .rdata')

    relocInfoList = []
    importInfoList = []
    stringTableOffset = fileHeader.PointerToSymbolTable + fileHeader.NumberOfSymbols * struct.calcsize('<8sIHHBB')
    for i in range(relocNum):
        offset = relocOffset + i * struct.calcsize('<IIH')
        reloc = IMAGE_RELOCATION(bof[offset:offset+struct.calcsize('<IIH')])
        offset = fileHeader.PointerToSymbolTable + reloc.SymbolTableIndex * struct.calcsize('<8sIHHBB')
        symbol = IMAGE_SYMBOL(bof[offset:offset+struct.calcsize('<8sIHHBB')])
        if symbol.N[:4] == b'\x00\x00\x00\x00':
            nameOffset = stringTableOffset + struct.unpack('<I', symbol.N[4:])[0]
            name = bof[nameOffset:].split(b'\0')[0]
        else:
            name = symbol.N.split(b'\0')[0]
        if b'__imp_' in name and b'$' in name: # dllFunc
            elems = name[6:].split(b'$')
            importInfoList += [[reloc.VirtualAddress, elems[0] + b'\x00', GetHash(elems[1])]]
        elif name == b'.rdata':
            importInfoList += [[reloc.VirtualAddress, name + b'\x00', 0]]
        elif symbol.Value != 0: # 非 bofFunc 的自定义函数
            relocInfoList += [[reloc.VirtualAddress, symbol.Value]]
        else:
            raise Exception('Not supported: ' + name.decode())

    bofFuncOffsetMap = dict()
    for i in range(fileHeader.NumberOfSymbols):
        offset = fileHeader.PointerToSymbolTable + i * struct.calcsize('<8sIHHBB')
        symbol = IMAGE_SYMBOL(bof[offset:offset+struct.calcsize('<8sIHHBB')])
        if symbol.N[:4] == b'\x00\x00\x00\x00':
            nameOffset = stringTableOffset + struct.unpack('<I', symbol.N[4:])[0]
            name = bof[nameOffset:].split(b'\0')[0]
        else:
            name = symbol.N.split(b'\0')[0]
        if b'$$' in name: # bofFunc
            bofFuncOffsetMap[symbol.Value] = name
    if len(bofFuncOffsetMap) == 0:
        raise Exception('BOF function not found, function name must include $$.')
    return text, rdata, importInfoList, bofFuncOffsetMap, relocInfoList

def Disassembly(hardCode, type):
    relocInfoList = None
    if type == 'bof':
        # .text; .rdata; [[relocOffset, dllName/.rdata, dllFuncHash/0], ...]; {offset:bofFuncName, ...}; [[relocOffset, 非 bofFunc 的自定义函数偏移], ...]
        # importInfoList 的重定位在 BOF Loader 中进行, 在 relocOffset 位置填充 dllFunc 指针或 .rdata 偏移
        # bofFuncOffsetMap 记录了可以调用的 bofFunc 偏移, 用于指示 BOF Loader 从机器码的什么位置开始运行
        # relocInfoList 的重定位在下面的代码中进行, 在 relocOffset 位置填充非 bofFunc 的自定义函数偏移
        hardCode, rdata, importInfoList, bofFuncOffsetMap, relocInfoList = ParseBOF(hardCode)
        with open('Disassembly\\rdata.bin', 'wb') as f:
            f.write(rdata)
        with open('Disassembly\\importInfoList.txt', 'w', encoding='UTF-8') as f:
            f.write(str(importInfoList))
        with open('Disassembly\\bofFuncOffsetMap.txt', 'w', encoding='UTF-8') as f:
            f.write(str(bofFuncOffsetMap))

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = cs.disasm(hardCode, 0)

    asms = ''
    relocIndex = 0
    for instruction in instructions:
        ops = instruction.op_str
        # nop dword ptr [rax + rax] 操作数没必要存在
        if instruction.mnemonic == 'nop':
            ops = ''
        # BOF 重定位
        if type == 'bof' and relocIndex < len(relocInfoList) and instruction.address <= relocInfoList[relocIndex][0] and instruction.address + len(instruction.bytes) >= relocInfoList[relocIndex][0]:
            # call 错误偏移 -> call 非 bofFunc 的自定义函数偏移
            if instruction.mnemonic == 'call' and ops[0].isdigit():
                ops = hex(relocInfoList[relocIndex][1])
                relocIndex += 1
            else:
                raise Exception(f'Not supported: {instruction.mnemonic} {ops}')
        asms += f'{hex(instruction.address)} {instruction.mnemonic} {ops}\n'

    with open('Disassembly\\asm.txt', 'w', encoding='UTF-8') as f:
        f.write(asms)
    print('\033[92m' + '[+] Save to Disassembly folder.\n' + '\033[0m')
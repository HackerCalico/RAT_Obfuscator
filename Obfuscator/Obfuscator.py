import re
import os
import ast
import time
import struct
import random
import binascii
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from EquReplace import EquReplace, cannotObf
from Disassembly import Disassembly, GetHash

cs = Cs(CS_ARCH_X86, CS_MODE_64)
ks = Ks(KS_ARCH_X86, KS_MODE_64)

def XorData(data, xor1, xor2):
    data = bytearray(data)
    for i in range(len(data)):
        data[i] = data[i] ^ ord(xor1) ^ ord(xor2)
    return data

def Obfuscate(type):
    with open('Disassembly\\asm.txt', 'r', encoding='UTF-8') as f:
        instructions = f.read().split('\n')
    bofHash = None
    if type == 'bof':
        # importInfoList [[relocOffset, dllName/.rdata, dllFuncHash/0], ...] 的重定位在 BOF Loader 中进行, 在 relocOffset 位置填充 dllFunc 指针或 .rdata 偏移
        # bofFuncOffsetMap {offset:bofFuncName, ...} 记录了可以调用的 bofFunc 偏移, 用于指示 BOF Loader 从机器码的什么位置开始运行
        with open('Disassembly\\rdata.bin', 'rb') as f:
            rdata = f.read()
        with open('Disassembly\\importInfoList.txt', 'r', encoding='UTF-8') as f:
            importInfoList = ast.literal_eval(f.read())
        with open('Disassembly\\bofFuncOffsetMap.txt', 'r', encoding='UTF-8') as f:
            bofFuncOffsetMap = ast.literal_eval(f.read())
        bofHash = GetHash(str(instructions).encode() + rdata)

    # 逐条指令等效替换
    obfAsms = '' # 等效替换后的指令集
    asmIndex = 0 # 当前指令下标
    relocIndex = 0
    asmOffsetMap = dict() # {需要重定位的指令:offset, ...}
    bofFuncAsmIndexMap = dict() # {bofFunc 第一条指令的下标:bofFuncName, ...}
    for i in range(len(instructions)):
        if instructions[i].rstrip() == '':
            continue
        elems = instructions[i].split(' ', 2)
        address = int(elems[0], 16)
        mnemonic = elems[1]
        ops = ''
        if len(elems) > 2:
            ops = elems[2]
        # jcc 的上一条指令不是 cmp / test, 不支持混淆
        if mnemonic[0] == 'j' and mnemonic != 'jmp' and 'cmp' not in instructions[i-1] and 'test' not in instructions[i-1]:
            print('\033[31m' + f'[-] The previous instruction of jcc must be cmp or test:\n{instructions[i-1]}\n{instructions[i]}' + '\033[0m')
            if type == 'bof':
                print('\033[31m' + 'Please use the -fno-optimize-sibling-calls flag.' + '\033[0m')
            elif type == 'shellcode':
                print('\033[31m' + 'Please use "Visual Studio 20XX (v143)" instead of "LLVM (clang-cl)".' + '\033[0m')
            elif type == 'exeFunc':
                print('\033[31m' + 'Please use the /Od flag.' + '\033[0m')
            return
        # jcc / jmp 非立即数, 不支持混淆
        if mnemonic[0] == 'j' and not ops[0].isdigit():
            print('\033[31m' + f'[-] Only supports obfuscating "jcc/jmp imm": {instructions[i]}' + '\033[0m')
            return
        # gs: 这种不支持混淆, 因为 keystone 编译的机器码不正确, 也不推荐用
        if ':' in ops:
            print('\033[31m' + f'[-] Obfuscation of ":" is not supported: {instructions[i]}\nKeystone does not support instructions like "mov rax, qword ptr gs:[0x60]".' + '\033[0m')
            return
        if mnemonic != 'int3': # nop 需要保留, 因为可能存在 jmp 到 nop 的情况
            asm = f'{mnemonic} {ops}'
            obfAsms += f'label{hex(address).replace("0x", "")}:\n'
            curObfAsms = EquReplace(asm) # 等效替换单条指令
            obfAsms += curObfAsms + '\n'
            if type == 'bof':
                if 'rip' in ops: # 当前指令需要重定位(BOF 指令中 RIP 所在的位置为 relocOffset, 需要填充 dllFunc 指针或 .rdata 偏移)
                    importInfoList[relocIndex][0] -= address # relocOffset - 当前指令偏移 = relocOffset 相对当前指令起始位置的偏移
                    relocIndex += 1
                if address in bofFuncOffsetMap: # 当前指令是 BOF 函数的第一条指令
                    bofFuncAsmIndexMap[asmIndex] = bofFuncOffsetMap[address]
                asmIndex += len(curObfAsms.split('\n'))
            elif type == 'exeFunc' and 'rip' in ops: # 当前指令中的 offset 需要重定位, 因为混淆后 rip 改变了, 例如 rip + offset
                if asm in asmOffsetMap:
                    print('\033[31m' + f'[-] Repeated: {asm}\nPlease try again.' + '\033[0m')
                    return
                else:
                    asmOffsetMap[asm] = address
    obfAsmList = obfAsms.rstrip().split('\n')
    print('\033[31m' + f'\n[!] Cannot be obfuscated:')
    print('\n'.join(cannotObf) + '\n' + '\033[0m')

    # 乱序处理(分成多个片段后打乱顺序, 通过 jmp 串联)
    order = [] # 片段存储顺序(snippetIndex)
    asmIndex = 0 # 当前指令下标
    snippet = '' # 当前片段
    snippetList = []
    snippetIndex = 0
    snippetAsmNum = 0 # 当前片段的指令数量
    snippetAsmNumList = []
    bofFuncSnippetIndexMap = dict() # {bofFunc 第一条指令所在的片段的下标:[bofFuncName, 该指令是当前片段第几条指令], ...}
    for i in range(len(obfAsmList)):
        snippet += obfAsmList[i] + '\n'
        if not ('label' in obfAsmList[i] and ':' in obfAsmList[i]): # 不是标签, 是指令
            snippetAsmNum += 1
            if type == 'bof':
                if asmIndex in bofFuncAsmIndexMap: # 当前指令是 bofFunc 的第一条指令
                    bofFuncSnippetIndexMap[snippetIndex] = [bofFuncAsmIndexMap[asmIndex], snippetAsmNum]
                asmIndex += 1
            # 当前片段结束
            if random.choice([False, False, False, True]) or i == len(obfAsmList) - 1:
                snippet = f'snippet{snippetIndex}:\n{snippet}'
                if i < len(obfAsmList) - 1:
                    snippet += f'jmp snippet{snippetIndex+1}'
                    snippetAsmNumList += [snippetAsmNum + 1]
                else:
                    snippetAsmNumList += [snippetAsmNum]
                snippetList += [snippet]
                order += [snippetIndex]
                snippet = ''
                snippetIndex += 1
                snippetAsmNum = 0
    random.shuffle(order) # 乱序
    obfAsms = ''  # 乱序后的指令集
    for i in order:
        obfAsms += f'{snippetList[i]}\n'
    addHeadAsms = 'jmp snippet0\n' + obfAsms

    if type == 'shellcode':
        offset = None
        addHeadCode, _ = ks.asm(addHeadAsms)
        if addHeadCode[0] == 0xEB:
            offset = addHeadCode[1]
        elif addHeadCode[0] == 0xE9:
            offset = struct.unpack('<I', bytes(addHeadCode[1:5]))[0]
        print('\033[92m' + '[+] ObfShellCode:' + '\033[0m')
        print('__attribute__((naked)) void ShellCode(...) {\n__asm {\n' + obfAsms + '}\n}\n' + f'((void(*)(...))((PBYTE)ShellCode + {offset}))(LoadLibraryA("user32"));')
        print('\033[31m' + '[!] Inline assembly requires the /O2 flag.' + '\033[0m')
        obfCode, _ = ks.asm(obfAsms)
        with open('ObfShellCode.bin', 'wb') as f:
            f.write(bytes(obfCode))
        print('\033[92m' + '[+] Save to ObfShellCode.bin' + '\033[0m')

    # 重定位 RIP 偏移
    elif type == 'exeFunc':
        needReloc = True # 还需要重定位
        addHeadCode = None
        while needReloc: # 需要多次重定位是因为每次重定位 offset 改变 -> 指令长度改变 -> 长短跳可能改变 -> rip 可能改变 -> 可能需要再次重定位
            needReloc = False
            addHeadCode, _ = ks.asm(addHeadAsms)
            instructions = cs.disasm(bytes(addHeadCode), 0)
            addHeadAsms = ''
            for instruction in instructions:
                asm = f'{instruction.mnemonic} {instruction.op_str}'
                addHeadAsms += f'label{hex(instruction.address).replace("0x", "")}:\n'
                if 'rip' in instruction.op_str and instruction.address != asmOffsetMap[asm]: # 当前指令中的 offset 需要重定位, 因为混淆后 rip 改变了, 例如 rip + offset
                    elems = re.findall(r'(.*rip\s)([+-]\s\w+)(.*)', instruction.op_str)[0]
                    offset = int(elems[1].replace(' ', ''), 16) - (instruction.address - asmOffsetMap[asm])
                    del asmOffsetMap[asm]
                    asm = f'{instruction.mnemonic} {elems[0]}+ {hex(offset)}{elems[2]}'.replace('+ -', '- ')
                    addHeadAsms += asm + '\n'
                    if asm in asmOffsetMap:
                        print('\033[31m' + f'[-] Repeated: {asm}\nPlease try again.' + '\033[0m')
                        return
                    else:
                        asmOffsetMap[asm] = instruction.address
                    needReloc = True
                elif (instruction.mnemonic == 'call' or instruction.mnemonic[0] == 'j') and instruction.op_str[0].isdigit() and '0xffffffff' not in instruction.op_str:
                    addHeadAsms += f'{instruction.mnemonic} label{instruction.op_str.replace("0x", "")}\n'
                else:
                    addHeadAsms += asm + '\n'
        with open('ObfFunc.bin', 'wb') as f:
            f.write(bytes(addHeadCode))
        print('\033[92m' + '[+] Save to ObfFunc.bin' + '\033[0m')

    elif type == 'bof':
        # 重定位乱序后 bofFuncSnippetIndexMap 中的片段下标
        for snippetIndex in list(bofFuncSnippetIndexMap):
            bofFuncName = bofFuncSnippetIndexMap[snippetIndex][0]
            snippetAsmNum = bofFuncSnippetIndexMap[snippetIndex][1]
            del bofFuncSnippetIndexMap[snippetIndex]
            bofFuncSnippetIndexMap[order.index(snippetIndex)] = [bofFuncName, snippetAsmNum]
        # 重定位乱序后 bofFuncOffsetMap 中的 bofFunc 偏移
        snippet = []
        snippetList = []
        snippetIndex = 0
        snippetAsmNum = 0 # 当前片段第几条指令
        bofFuncOffsetMap = dict() # {bofFuncName:混淆后的偏移, ...}
        obfCode, _ = ks.asm(obfAsms)
        obfCode = bytes(obfCode)
        instructions = cs.disasm(obfCode, 0)
        for instruction in instructions:
            snippetAsmNum += 1
            if snippetIndex in bofFuncSnippetIndexMap and snippetAsmNum == bofFuncSnippetIndexMap[snippetIndex][1]: # 当前指令是 bofFunc 的第一条指令
                bofFuncOffsetMap[bofFuncSnippetIndexMap[snippetIndex][0]] = instruction.address
            snippet += [instruction]
            # 当前片段结束
            if snippetAsmNum == snippetAsmNumList[order[snippetIndex]]:
                snippetList += [snippet]
                snippet = []
                snippetIndex += 1
                snippetAsmNum = 0
        # 还原片段执行顺序
        instructions = []
        for i in range(len(order)):
            snippetIndex = order.index(i)
            instructions += snippetList[snippetIndex]
        # 重定位 importInfoList 中的 relocOffset
        relocIndex = 0
        for instruction in instructions:
            if 'rip' in instruction.op_str: # 当前指令需要重定位(BOF 指令中 RIP 所在的位置为 relocOffset, 需要填充 dllFunc 指针或 .rdata 偏移)
                importInfoList[relocIndex][0] += instruction.address # relocOffset 相对当前指令起始位置的偏移 + 当前指令偏移 = relocOffset
                relocIndex += 1
        # 构造 BOF Loader 可加载的 Payload
        xor1 = os.urandom(1)
        while xor1 == b'\x00':
            xor1 = os.urandom(1)
        xor2 = os.urandom(1)
        while xor2 == b'\x00' or xor1 == xor2:
            xor2 = os.urandom(1)
        importInfoListBin = b''
        for [offset, dllName, funcHash] in importInfoList:
            importInfoListBin += struct.pack('<H', offset) + dllName + struct.pack('<i', funcHash)
        bofFuncOffsetMapBin = b''
        for bofFuncName, offset in bofFuncOffsetMap.items():
            print(f'{bofFuncName.decode()} Hash: {GetHash(bofFuncName)}')
            bofFuncOffsetMapBin += struct.pack('<i', GetHash(bofFuncName)) + struct.pack('<H', offset)
        lens = struct.pack('<H', len(rdata)) + struct.pack('<H', len(obfCode)) + struct.pack('<H', len(importInfoListBin)) + struct.pack('<H', len(bofFuncOffsetMapBin))
        print('BOF Hash:', bofHash)
        print('\033[31m' + '[!] Obfuscation of .rdata is not supported.' + '\033[0m')
        print('\033[31m' + '[!] Please use the BOF_Loader from the example to load.' + '\033[0m')
        obfBOF = XorData(lens + b'\x01' + importInfoListBin + bofFuncOffsetMapBin + rdata + obfCode, xor1, xor2) + xor1 + xor2
        with open('ObfBOF.bin', 'wb') as f:
            f.write(bytes(obfBOF))
        print('\033[92m' + '[+] Save to ObfBOF.bin' + '\033[0m')

if __name__ == '__main__':
    print('''██████╗  █████╗ ████████╗    ██████╗ ██████╗ ███████╗██╗   ██╗███████╗ ██████╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══██╔══╝   ██╔═══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║   ██║      ██║   ██║██████╔╝█████╗  ██║   ██║███████╗██║     ███████║   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║   ██║      ██║   ██║██╔══██╗██╔══╝  ██║   ██║╚════██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║   ██║      ╚██████╔╝██████╔╝██║     ╚██████╔╝███████║╚██████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
https://github.com/HackerCalico/RAT_Obfuscator\nDue to complex code logic and varying conditions, it is currently in the testing phase.''')
    random.seed(time.time())
    print('x64 only.\n1.Disassembly\n2.Obfuscate BOF\n3.Obfuscate ShellCode\n4.Obfuscate EXE functions\n5.Instruction obfuscation test')
    choice = input('\033[94m' + 'choice: ' + '\033[0m')
    if choice == '1':
        path = input('\033[94m' + 'Path: ' + '\033[0m')
        if path[-2:] == '.o':
            with open(path, 'rb') as f:
                hardCode = f.read()
            Disassembly(hardCode, 'bof')
        elif path[-4:] == '.txt':
            with open(path, 'r', encoding='UTF-8') as f:
                hardCode = f.read().replace('\n', '').replace(' ', '')
            Disassembly(binascii.unhexlify(hardCode), 'asm')
    elif choice == '2':
        Obfuscate('bof')
    elif choice == '3':
        Obfuscate('shellcode')
    elif choice == '4':
        Obfuscate('exeFunc')
    elif choice == '5':
        instruction = input('\033[94m' + 'Instruction: ' + '\033[0m')
        for i in range(10):
            print(f'\n{i+1}th obfuscate:')
            EquReplace(instruction)
import re
import os
import time
import random
import binascii
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def GenerateGarbage(size):
    garbage = b''
    for i in range(size):
        if len(garbage) > size:
            break
        if i % 2 == 0:
            garbage += os.urandom(random.randint(1, 10))
        else:
            garbage += b'\xE9' + random.randint(200, 400).to_bytes(4, byteorder='little', signed=True)
    return garbage

def ObfShellCode(shellcode, isShellCode=True):
    shellcode = binascii.unhexlify(shellcode)
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = cs.disasm(shellcode, 0)

    # addr: 指令原地址; nextAddr: 下一条指令原地址(执行顺序)
    order = [] # 执行顺序 [addr1, addr2, ...]
    asmInfo = dict() # {addr1:{asm:'指令文本', garbage:'garbage硬编码', hardCode:'指令硬编码', jmp:'jmp硬编码', start:指令首地址(乱序), end:指令尾地址(乱序)}, ...}
    for instruction in instructions:
        order += [instruction.address]
        asmInfo[instruction.address] = dict()
        asmInfo[instruction.address]['asm'] = instruction.mnemonic + ' ' + instruction.op_str
        asmInfo[instruction.address]['garbage'] = GenerateGarbage(5)
        asmInfo[instruction.address]['hardCode'] = instruction.bytes
    outOfOrder = order.copy() # 存储顺序(乱序) [addr5, addr1, ...]
    random.shuffle(outOfOrder)

    obfCode = GenerateGarbage(100)
    end = len(obfCode)
    if not isShellCode: # 如果是混淆 EXE 函数, 则最开头要加一个 jmp
        end += 5
    for addr in outOfOrder:
        # 计算指令的首地址(乱序)
        asmInfo[addr]['start'] = end + len(asmInfo[addr]['garbage'])
        # 计算指令的尾地址(乱序)
        # jmp 立即数(偏移地址) / jcc 立即数(偏移地址) 全部改用 "长跳", 因为不知道乱序后跳转偏移是否超过 -128～127
        if asmInfo[addr]['asm'][0] == 'j':
            if 'jmp' in asmInfo[addr]['asm']:
                hardCodeLength = 5 # EB XX -> E9 XX XX XX XX
            else:
                hardCodeLength = 6 # 7? XX -> 0F 8? XX XX XX XX
        else:
            hardCodeLength = len(asmInfo[addr]['hardCode'])
        end = asmInfo[addr]['end'] = asmInfo[addr]['start'] + hardCodeLength + 5 # 5 为串联用的 jmp 硬编码长度

    # 构造串联用的 jmp 硬编码
    # 跳转偏移 = 下一条指令(执行顺序)首地址(乱序) - 当前指令尾地址(乱序)
    for i in range(len(order)-1):
        addr = order[i]
        nextAddr = order[i+1]
        asmInfo[addr]['jmp'] = b'\xE9' + (asmInfo[nextAddr]['start'] - asmInfo[addr]['end']).to_bytes(4, byteorder='little', signed=True)
    asmInfo[order[len(order)-1]]['jmp'] = os.urandom(5) # 执行顺序最后一条指令

    # 拼接每组指令(乱序): garbage + 指令硬编码 + jmp
    for addr in outOfOrder:
        # 对 call imm; jmp imm; jcc imm; rip + imm 的立即数进行重定位, 因为乱序后指令的位置变了
        if not isShellCode and 'rip' in asmInfo[addr]['asm']: # RIP + 立即数(偏移)
            offset = int.from_bytes(asmInfo[addr]['hardCode'][-4:], byteorder='little', signed=True)
            offset -= asmInfo[addr]['start'] - addr
            asmInfo[addr]['hardCode'] = asmInfo[addr]['hardCode'][:-4] + offset.to_bytes(4, byteorder='little', signed=True)
        elif 'call' in asmInfo[addr]['asm']: # call 立即数(偏移地址)
            imm = re.findall(r'^[a-zA-Z]+\s+(?:0x)?([a-fA-F\d]+)$', asmInfo[addr]['asm'])
            if len(imm) > 0:
                offsetAddr = int(imm[0], 16)
                if offsetAddr in asmInfo:
                    asmInfo[addr]['hardCode'] = b'\xE8' + (asmInfo[offsetAddr]['start']-(asmInfo[addr]['end']-5)).to_bytes(4, byteorder='little', signed=True)
                else: # 非 ShellCode 存在 call 0xfffffffffffxxxxx 的情况
                    offsetAddr -= 0x10000000000000000
                    asmInfo[addr]['hardCode'] = b'\xE8' + (offsetAddr-(asmInfo[addr]['end']-5)).to_bytes(4, byteorder='little', signed=True)
        elif asmInfo[addr]['asm'][0] == 'j': # jmp 立即数(偏移地址) / jcc 立即数(偏移地址)
            imm = re.findall(r'^[a-zA-Z]+\s+(?:0x)?([a-fA-F\d]+)$', asmInfo[addr]['asm'])
            if len(imm) > 0:
                offsetAddr = int(imm[0], 16)
                if asmInfo[addr]['hardCode'][0] == 0xEB or asmInfo[addr]['hardCode'][0] == 0xE9:
                    hardCode = b'\xE9'
                elif asmInfo[addr]['hardCode'][0] == 0x0F:
                    hardCode = asmInfo[addr]['hardCode'][:2]
                else:
                    hardCode = b'\x0F' + (asmInfo[addr]['hardCode'][0]+0x10).to_bytes(1, byteorder='little')
                asmInfo[addr]['hardCode'] = hardCode + (asmInfo[offsetAddr]['start']-(asmInfo[addr]['end']-5)).to_bytes(4, byteorder='little', signed=True)
        obfCode += asmInfo[addr]['garbage'] + asmInfo[addr]['hardCode'] + asmInfo[addr]['jmp']
    obfCode += GenerateGarbage(100)
    # 混淆 EXE 函数, 开头添加 jmp
    if not isShellCode:
        obfCode = b'\xE9' + (asmInfo[order[0]]['start']-5).to_bytes(4, byteorder='little', signed=True) + obfCode

    if isShellCode:
        print('执行顺序:')
        for addr in order:
            print(asmInfo[addr]['asm'], '- start:', asmInfo[addr]['start'])
        print()
        print('以上按照 "执行顺序" 输出了指令信息.\n'
              '如果你的 ShellCode 只有一个函数, 那么混淆后的 ShellCode 的调用地址即为 "执行顺序" 第一条指令的 start(乱序后指令首地址).\n'
              '如果有多个函数, 请自行找到调用地址. 比如本项目样例有两个函数, 可以通过 ctrl+F 快速定位到第一个函数结尾的 ret 以及下方的 int3,'
              '\n而 int3 之后的 mov qword ptr [rsp + 8], rcx 即为第二个函数的第一条指令, 其 start 即为调用地址.')
        start = input('\033[94m' + 'Please enter start: ' + '\033[0m')
        print()
        print('\033[92m' + '[+] 测试代码(本项目样例参数):' + '\033[0m')
        print('char buf[] = "' + ''.join([f'\\x{byte:02x}' for byte in obfCode]) + '";\nPBYTE p = (PBYTE)VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);\nmemcpy(p, buf, sizeof(buf));\n((void(*)(...))(p + ' + start + '))(LoadLibraryA("user32"));')
        print()
    with open('ObfCode.bin', 'wb') as f:
        f.write(obfCode)
    print('\033[92m' + '[+] 二进制保存至 ObfCode.bin' + '\033[0m')

if __name__ == '__main__':
    print('''██████╗  █████╗ ████████╗    ██████╗ ██████╗ ███████╗██╗   ██╗███████╗ ██████╗ █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══██╔══╝   ██╔═══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║   ██║      ██║   ██║██████╔╝█████╗  ██║   ██║███████╗██║     ███████║   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║   ██║      ██║   ██║██╔══██╗██╔══╝  ██║   ██║╚════██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║   ██║      ╚██████╔╝██████╔╝██║     ╚██████╔╝███████║╚██████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
https://github.com/HackerCalico/RAT_Obfuscator''')
    random.seed(time.time())
    while True:
        choice = input('1.混淆 ShellCode\n2.混淆 EXE 函数\n选择: ')
        path = input('\033[94m' + 'Please enter path: ' + '\033[0m')
        print()
        with open(path, 'r', encoding='UTF-8') as file:
            shellcode = file.read()
        if choice == '1':
            ObfShellCode(shellcode.replace('\n', '').replace(' ', ''))
        elif choice == '2':
            ObfShellCode(shellcode.replace('\n', '').replace(' ', ''), False)
        print()
import re
import random

cannotObf = []

reg64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsp', 'rbp']
reg32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esp', 'ebp']
reg16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'sp', 'bp']
regLow8 = ['al', 'bl', 'cl', 'dl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'spl', 'bpl']

def GetAsmInfo(asm):
    elems = asm.split(' ', 1)
    mnemonic = elems[0]
    ops = []
    if len(elems) > 1:
        ops = elems[1].split(', ')

    opType1 = ''
    if len(ops) > 0:
        if '[' in ops[0]:
            opType1 = '[]'
        elif len(ops[0]) > 0:
            opType1 = 'r'

    opType2 = ''
    if len(ops) > 1:
        if '[' in ops[1]:
            opType2 = '[]'
        elif ops[1][0].isdigit() or ops[1][0] == '-':
            opType2 = 'i'
        else:
            opType2 = 'r'
    return mnemonic, ops, opType1, opType2

def SetToFF(op):
    # or r, rand1; or r, (~rand1 | rand2)
    rand1 = random.randint(0x10, 0xFF)
    rand2 = random.randint(0x10, 0xFF)
    return f'or {op}, {hex(rand1)}\nor {op}, {hex(~rand1 | rand2)}'

def SetToZero(op):
    index = random.randint(1, 4)
    if index == 1: # mov r, 0
        return f'mov {op}, 0'
    elif index == 2: # sub r, r
        return f'sub {op}, {op}'
    elif index == 3: # xor r, r
        return f'xor {op}, {op}'
    elif index == 4: # and r, rand1; and r, (~rand1 & rand2)
        rand1 = random.randint(0x10, 0xFF)
        rand2 = random.randint(0x10, 0xFF)
        return f'and {op}, {hex(rand1)}\nand {op}, {hex(~rand1 & rand2)}'

def AddSubLeaImm(op, opType, imm, useLea=False):
    if useLea:
        index = 3
    elif opType == 'r' and op in reg64 + reg32:
        index = random.randint(1, 3)
    else:
        index = random.randint(1, 2)
    if index == 1: # add ?, i
        return f'add {op}, {hex(imm)}'
    elif index == 2: # sub ?, -i
        return f'sub {op}, {hex(-imm)}'
    elif index == 3: # lea r, [r + i]
        return f'lea {op}, [{op} + {hex(imm)}]'.replace('+ -', '- ')

def ObfMnemonic(mnemonic, ops, opType1, opType2, instruction):
    # push r
    if mnemonic == 'push' and opType1 == 'r':
        return f'sub rsp, 8\nmov qword ptr [rsp], {ops[0]}'

    # pop r
    if mnemonic == 'pop' and opType1 == 'r':
        return f'mov {ops[0]}, qword ptr [rsp]\nadd rsp, 8'

    # mov r1, r2
    if mnemonic == 'mov' and opType1 == 'r' and opType2 == 'r':
        index = 0
        if ops[0] == ops[1]:
            if ops[1] in reg64 + reg32:
                index = 5
        elif ops[1] in reg64 + reg32:
            index = random.randint(1, 5)
        else:
            index = random.randint(1, 4)
        if index == 1: # r1->0; or r1, r2
            return f'{SetToZero(ops[0])}\nor {ops[0]}, {ops[1]}'
        elif index == 2: # r1->0; xor r1, r2
            return f'{SetToZero(ops[0])}\nxor {ops[0]}, {ops[1]}'
        elif index == 3: # r1->0; add r1, r2
            return f'{SetToZero(ops[0])}\nadd {ops[0]}, {ops[1]}'
        elif index == 4: # r1->FF; and r1, r2
            return f'{SetToFF(ops[0])}\nand {ops[0]}, {ops[1]}'
        elif index == 5: # lea r1, [r2]
            return f'lea {ops[0]}, [{ops[1]}]'
    
    # add r1, r2 -> lea r1, [r1 + r2]
    if mnemonic == 'add' and opType1 == 'r' and opType2 == 'r' and ops[0] in reg64 + reg32 and ops[1] in reg64 + reg32:
        return f'lea {ops[0]}, [{ops[0]} + {ops[1]}]'

    # inc ?
    if mnemonic == 'inc':
        return AddSubLeaImm(ops[0], opType1, 1)

    # dec ?
    if mnemonic == 'dec':
        return AddSubLeaImm(ops[0], opType1, -1)

    # xor r, r
    if mnemonic == 'xor' and ops[0] == ops[1]:
        return SetToZero(ops[0])

    # imul r, r, 0
    if mnemonic == 'imul' and len(ops) == 3 and ops[0] == ops[1] and ops[2] == '0':
        return SetToZero(ops[0])
    return instruction

# 检查 [] 中重复使用的寄存器, 例如 lea eax, [rax + 1] 中的 rax
def IncludeReg(indAddrOp, reg):
    index = None
    if reg in reg64:
        index = reg64.index(reg)
    elif reg in reg32:
        index = reg32.index(reg)
    elif reg in reg16:
        index = reg16.index(reg)
    elif reg in regLow8:
        index = regLow8.index(reg)
    if reg32[index] in indAddrOp:
        return reg32[index]
    elif reg64[index] in indAddrOp:
         return reg64[index]
    return False

def ObfIndAddr(obfAsm, useLea=False):
    elems = re.findall(r'(.*\[)([a-zA-Z]\w+)([^\w].*)', obfAsm)
    if elems and '*' not in obfAsm:
        reReg = None # [] 中重复使用的寄存器, 例如 lea eax, [rax + 1] 中的 rax
        indAddrOp = None # [] 类型的操作数, 例如 lea eax, [rcx + 1] 中的 [rcx + 1]
        mnemonic, ops, opType1, opType2 = GetAsmInfo(obfAsm)
        # 检查 [] 中重复使用的寄存器
        if opType1 == 'r':
            indAddrOp = ops[1]
            reReg = IncludeReg(ops[1], ops[0])
        elif opType2 == 'r':
            indAddrOp = ops[0]
            reReg = IncludeReg(ops[0], ops[1])
        # eg: lea rax, [rcx + 1] -> add rcx, 2; lea rax, [rcx - 1]; sub rcx, 2
        if opType2 == 'i' or not reReg:
            reg = elems[0][1] # [] 中第一个寄存器, 例如 [rcx + 1] 中的 rcx
            rand = random.randint(0x10, 0xFF)
            obfFormula = f'{elems[0][0]}{reg} + {hex(-rand)}{elems[0][2]}'.replace('+ -', '- ')
            return f'{AddSubLeaImm(reg, "r", rand)}\n{obfFormula}\n{AddSubLeaImm(reg, "r", -rand, useLea)}'
        # eg: lea eax, [rax + 1] -> push rcx; mov rcx, rax; add rcx, 2; lea eax, [rcx - 1]; pop rcx
        elif reReg in reg64 and reReg not in ['rsp', 'rbp'] and indAddrOp.count(reReg) == 1:
            # 随机找出一个当前指令未使用的 x64 寄存器(不包括栈寄存器)
            notUseRegs = reg64[:14]
            regs = re.findall(r'\b[a-zA-Z]\w+\b', indAddrOp)
            for reg in regs:
                if reg in notUseRegs:
                    notUseRegs.remove(reg)
            notUseReg = random.choice(notUseRegs)
            # 生成混淆指令序列
            rand = random.randint(0x10, 0xFF)
            obfFormula = f'{notUseReg} + {hex(-rand)}'.replace('+ -', '- ')
            if indAddrOp == ops[0]:
                obfFormula = f'{mnemonic} {indAddrOp.replace(reReg, obfFormula)}, {ops[1]}'
            elif indAddrOp == ops[1]:
                obfFormula = f'{mnemonic} {ops[0]}, {indAddrOp.replace(reReg, obfFormula)}'
            return f'push {notUseReg}\nmov {notUseReg}, {reReg}\n{AddSubLeaImm(notUseReg, "r", rand)}\n{obfFormula}\npop {notUseReg}'
    return obfAsm

def ObfOps(obfAsms):
    obfAsmList = obfAsms.split('\n')
    obfAsms = ''
    for obfAsm in obfAsmList:
        mnemonic, ops, opType1, opType2 = GetAsmInfo(obfAsm)
        # op2 为 imm
        # eg: mov qword ptr [rax + 1], 1
        #  -> mov qword ptr [rax + 1], 0; add qword ptr [rax + 1], 1
        #  -> add rax, 2; mov qword ptr [rax - 1], 0; sub rax, 2; add rax, 2; add qword ptr [rax - 1], 1; sub rax, 2;
        if mnemonic in ['mov', 'add', 'sub'] and opType2 == 'i' and len(ops[1].replace('0x', '').replace('-', '')) <= 7: # 指令的立即数有范围限制
            rand1 = rand2 = random.randint(0x10, 0xFF)
            imm = int(ops[1], 16)
            if mnemonic == 'sub':
                imm *= -1
                rand2 *= -1
            obf1 = ObfIndAddr(f'{mnemonic} {ops[0]}, {hex(rand1)}')
            obf2 = ObfIndAddr(AddSubLeaImm(ops[0], opType1, imm-rand2))
            obfAsms += f'{obf1}\n{obf2}\n'
        # 存在 []
        # eg: lea rax, [rcx + 1] -> add rcx, 2; lea rax, [rcx - 1]; sub rcx, 2
        # eg: lea eax, [rax + 1] -> push rcx; mov rcx, rax; add rcx, 2; lea eax, [rcx - 1]; pop rcx
        elif ('mov' in mnemonic or mnemonic in ['lea', 'add', 'sub', 'and', 'or', 'xor', 'cmp', 'test']) and '[' in obfAsm:
            obfAsms += f'{ObfIndAddr(obfAsm, mnemonic in ["cmp", "test"])}\n'
        else:
            obfAsms += f'{obfAsm}\n'
    return obfAsms.rstrip()

def EquReplace(instruction):
    mnemonic, ops, opType1, opType2 = GetAsmInfo(instruction)
    print('\nBefore: \n' + '\033[94m' + instruction + '\033[0m')

    if 'rip' in instruction:
        return instruction
    if mnemonic == 'call' or mnemonic[0] == 'j':
        if ops[0][0].isdigit():
            if '0xffffffff' in ops[0]: # exeFunc 存在 call 小于指令集首地址的情况
                return instruction
            else:
                return f'{mnemonic} label{ops[0].replace("0x", "")}'
        else:
            print('\033[31m' + f'[!] Cannot be obfuscated: {instruction}' + '\033[0m')
            return instruction

    # 原指令 -> 操作数易变形的指令序列
    obfAsms = ObfMnemonic(mnemonic, ops, opType1, opType2, instruction)
    print('ObfMnemonic: \n' + '\033[95m' + obfAsms + '\033[0m')
    # 混淆操作数
    obfAsms = ObfOps(obfAsms)
    print('ObfOps: \n' + '\033[93m' + obfAsms + '\033[0m')

    if instruction in obfAsms and not (mnemonic == 'xor' and ops[0] == ops[1]): # xor r, r 混淆后不变是可接受的
        global cannotObf
        cannotObf += [instruction]
        print('\033[31m' + f'[!] Cannot be obfuscated: {instruction}' + '\033[0m')
    return obfAsms
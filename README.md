# RAT_Obfuscator

### 请给我 Star 🌟，非常感谢！这对我很重要！

### Please give me Star 🌟, thank you very much! It is very important to me!

### 1. 介绍

https://github.com/HackerCalico/RAT_Obfuscator

Amazing 二进制混淆器，支持混淆 ShellCode，甚至支持混淆 EXE 中的函数机器码。

![RAT_Obfuscator.jpg (1000×300)](https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/RAT_Obfuscator.jpg)

### 2. 效果 & 优势

(1) 不存在自解密等任何加解密操作，所以无需 RWX。

(2) 完全混淆；不会出现任何原指令序列；不会向混淆的机器码中添加任何混淆器自己的特征，每次混淆特征 100% 不同。

(3) 无法识别，在未知调用首地址的情况下，无法正常反汇编。所以无需先在 RW 中解密，再改为 RX 运行，可直接嵌入 .text 中运行。

![1.png (422×335)](https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/1.png)

(4) 仅支持混淆纯指令型机器码。

<mark>指令存储顺序完全随机打乱，间隙填充随机 Garbage (大概率生成混淆 jmp)。</mark>

<mark>指令执行顺序通过 jmp 串联。</mark>

<img src="https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/2.png" title="" alt="2.png (682×624)" width="402">

### 3. 使用方法

<mark>请先尝试项目提供的 PE 样例：ExamplePE\x64\Release\ExamplePE.exe</mark>

ExamplePE.exe 包含一个 ShellCode 位于 .shell；以及一个复杂的普通函数位于 .func

(1) 混淆 ShellCode

该 ShellCode 包含两个函数，我们要调用下面的函数，它会调用上面的函数。

将 ShellCode 复制到 Obfuscator\shellcode.txt。

```bash
> python Obfuscator.py
1.混淆 ShellCode
2.混淆 EXE 函数
选择: 1
Please enter path: shellcode.txt

执行顺序:
mov qword ptr [rsp + 0x10], rdx - start: 352
....
ret  - start: 1458
....
int3  - start: 1694
mov qword ptr [rsp + 8], rcx - start: 1402
....
ret  - start: 696

Please enter start:
```

可以看到按照 "执行顺序" 输出了每条指令的文本和 start，start 为指令存储顺序被打乱后该指令新的首地址。

我们要调用 ShellCode 的第二个函数，可以看到第一个函数结尾的 ret 和 int3，后面的 mov qword ptr [rsp + 8], rcx 即为第二个函数的第一条指令，其首地址为 1402。

```bash
Please enter start: 1402

[+] 测试代码(本项目样例参数):
char buf[] = "\xa1....\x3d";
PBYTE p = (PBYTE)VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(p, buf, sizeof(buf));
((void(*)(...))(p + 1402))(LoadLibraryA("user32"));

[+] 二进制保存至 ObfCode.bin
```

运行测试代码即可。

(2) 混淆 EXE 函数

.func 中其实有两个函数，第二个函数仅起占位作用，因为第一个函数混淆后会变大，覆盖时会超出原位置。

两个函数的界限可简单通过第一个函数结尾的 C3 和后面有规律的字节码看出，将 .func 第一个函数的机器码复制到 Obfuscator\func.txt。

![3.png (724×179)](https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/3.png)

```bash
> python Obfuscator.py
1.混淆 ShellCode
2.混淆 EXE 函数
选择: 2
Please enter path: func.txt

[+] 二进制保存至 ObfCode.bin
```

将 ObfCode.bin 直接覆盖到第一个函数的首地址处，运行 EXE 即可。

### 4. 注意事项

(1) 为了防止杀软通过栈回溯定位到机器码，请自行编写欺骗函数来调用 Windows Api。

(2) EXE 函数混淆后，顶部会有一个 jmp，如果你发现函数上方还有多余的空间，请自行补充一些 Garbage 来掩护 jmp。

![4.png (724×88)](https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/4.png)

### 5. 功能实现

混淆示例：

```bash
混淆前
1 mov rax, 0x1
2 ret
3 mov rax, 0x2
4 mov rax, 0x3
5 jmp 6
6 call 1
7 ret
```

```bash
混淆后
———————————————————— Garbage 包含混淆 jmp
———————————————————— Garbage 包含混淆 jmp
1 ret
  jmp 6
———————————————————— Garbage 包含混淆 jmp
2 ret
———————————————————— Garbage 包含混淆 jmp
———————————————————— Garbage
3 mov rax, 0x1
  jmp 1
———————————————————— Garbage 包含混淆 jmp
4 mov rax, 0x3
  jmp 7
———————————————————— Garbage 包含混淆 jmp
5 call 3
  jmp 2
———————————————————— Garbage 包含混淆 jmp
6 mov rax, 0x2
  jmp 4
———————————————————— Garbage 包含混淆 jmp
7 jmp 5
  jmp 5
———————————————————— Garbage 包含混淆 jmp
———————————————————— Garbage 包含混淆 jmp
```

<mark>具体实现请看代码，下面对混淆流程进行简要概括：</mark>

(1) 将每条指令分别按 "执行顺序"、"乱序" 排序，"乱序" 即为混淆后的存储顺序。

(2) 根据 "乱序" 重新计算每组指令的 "首地址" 和 "尾地址"。

如上例中第一组 ret 的 "首地址" = len(前面的 Garbage)；"尾地址" = "首地址" + len(ret) + len(jmp)。

(3) 根据 "执行顺序"、"乱序" 的 "首地址" 和 "尾地址"，计算出串联用的 jmp 跳转偏移。

```bash
跳转偏移 = 下一条指令(执行顺序)首地址(乱序) - 当前指令尾地址(乱序)
```

如上例中 mov rax, 0x1 后面串联用的 jmp 跳转偏移 = 1 - 3

(4) 对 call imm; jmp imm; jcc imm; rip + imm 的立即数进行重定位。

如上例中混淆前的 jmp 6 混淆后为 jmp 5，因为 "乱序" 后指令的位置变了。

ShellCode 和 EXE 函数的主要区别在于：

EXE 函数的指令中可能存在 rip + imm  以及 call 0xfffffffffffxxxxx 的情况，处理方式依然是对立即数进行重定位。

rip + imm 因为 "乱序" 导致 rip 改变，所以要对 imm 进行重定位。

call 0xfffffffffffxxxxx 调用的函数地址小于当前 EXE 函数的首地址，所以要注意对负数的处理。

(5) 将每组 Garbage + 指令 + jmp 拼接。

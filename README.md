# RAT_Obfuscator

### 请给我 Star 🌟，非常感谢！这对我很重要！

### Please give me Star 🌟, thank you very much! It is very important to me!

### 1. 介绍

https://github.com/HackerCalico/RAT_Obfuscator

Magical 二进制混淆器，支持混淆 x64 的 EXE、BOF、ShellCode。

![RAT_Obfuscator.jpg (1000×300)](https://raw.githubusercontent.com/HackerCalico/RAT_Obfuscator/refs/heads/main/Image/RAT_Obfuscator.jpg)

### 2. 效果 & 优势

(1) 不存在自解密等任何加解密操作，所以无需 RWX。如果是 ShellCode，混淆后可直接通过内联汇编调用，无需申请内存。

(2) 逐条指令混淆，先将所有汇编指令等效替换为随机生成的等效指令序列，再随机分片打乱。保证每次混淆结果截然不同，并且不会添加额外的混淆器特有的函数。

### 3. 使用方法

<mark>请先尝试 Example 中的样例：</mark>

(1) Example\ShellCode 无需解释。

(2) Example\BOF\bof.o 包含两个可调用的 BOF 函数。编译使用的 clang 来自 llvm-mingw-20240903-ucrt-x86_64，将 bin 添加至环境变量即可。

https://github.com/mstorsjo/llvm-mingw/releases/download/20240903/llvm-mingw-20240903-ucrt-x86_64.zip

(3) Example\BOF_Loader 用于加载运行本项目混淆后的 BOF，当然该加载器本身也可以被混淆，需要配置 clang 以支持 x64 内联汇编。

Visual Studio Installer ---> 单个组件 ---> LLVM (clang-cl) 和 Clang ---> 安装

<mark>混淆 ShellCode</mark>

将 Example\ShellCode\x64\Release\ShellCode.exe 的 .shell 复制到 Obfuscator\shellcode.txt

反汇编：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 1
Path: shellcode.txt
[+] Save to Disassembly folder.
```

混淆：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 3
....
[+] ObfShellCode:
__attribute__((naked)) void ShellCode(...) {
__asm {
snippet58:
mov rdi, rax
....
sub r8, -0x25
jmp snippet57
}
}
((void(*)(...))((PBYTE)ShellCode + 1050))(LoadLibraryA("user32"));
[!] Inline assembly requires the /O2 flag.
[+] Save to ObfShellCode.bin
```

创建一个 C++ 项目粘贴生成的代码即可调用，LoadLibraryA("user32") 是样例 ShellCode 的参数。

需要开启优化(/O2)，以及配置 clang 以支持 x64 内联汇编：Visual Studio Installer ---> 单个组件 ---> LLVM (clang-cl) 和 Clang ---> 安装

<mark>混淆 BOF</mark>

将 Example\BOF\bof.o 复制到 Obfuscator\bof.o

反汇编：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 1
Path: bof.o
[+] Save to Disassembly folder.
```

混淆：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 2
....
ExecuteCmd$$ Hash: -504283653
GetFileInfoList$$ Hash: 1280936002
BOF Hash: 1169983540
[!] Obfuscation of .rdata is not supported.
[!] Please use the BOF_Loader from the example to load.
[+] Save to ObfBOF.bin
```

运行 Example\BOF_Loader 即可调用两个 BOF 函数。

<mark>混淆 EXE 函数</mark>

将 Example\BOF_Loader\x64\Release\BOF_Loader.exe 复制到 Example\BOF_Loader\BOF_Loader.exe

将 BOF_Loader.exe 的 .func 复制到 Obfuscator\func.txt，删除末尾所有的 48 C7 C0 00 00 00 00 以及 CC，它们仅起占位作用，因为混淆后指令集会更长。

反汇编：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 1
Path: func.txt
[+] Save to Disassembly folder.
```

混淆：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 4
....
[+] Save to ObfFunc.bin
```

将 ObfFunc.bin 的机器码覆盖 Example\BOF_Loader\BOF_Loader.exe 原本的 .func。

<mark>指令混淆测试</mark>

测试单条指令的混淆情况：

```bash
> python Obfuscator.py
1.Disassembly
2.Obfuscate BOF
3.Obfuscate ShellCode
4.Obfuscate EXE functions
5.Instruction obfuscation test
choice: 5
Instruction: mov rax, rcx

1th obfuscate:

Before: 
mov rax, rcx
ObfMnemonic: 
xor rax, rax
xor rax, rcx
ObfOps: 
xor rax, rax
xor rax, rcx
....
10th obfuscate:

Before: 
mov rax, rcx
ObfMnemonic: 
mov rax, 0
add rax, rcx
ObfOps: 
mov rax, 0xab
push rbx
mov rbx, rax
sub rbx, -0x54
lea rax, [rbx - 0x54 - 0xab]
pop rbx
add rax, rcx
```

### 4. 注意事项

(1) 建议自行混淆 .rdata。

(2) 建议自行编写反栈回溯函数来调用 Windows Api。

(3) 建议混淆 EXE 函数后在 .func 上方自行添加乱码来掩护 .func 开头的 jmp。
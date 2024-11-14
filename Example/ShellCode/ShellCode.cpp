#include <iostream>
#include <windows.h>

/*
* ⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️
* 1.Release x64
* 2.C/C++
* 常规: SDL检查(否)
* 优化: 优化(已禁用)
* 代码生成: 运行库(多线程); 安全检查(禁用安全检查)
* 3.链接器
* 清单文件: 生成清单(否)
* 调试: 生成调试信息(否)
*/

using namespace std;

PBYTE GetMessageBoxA(PBYTE pUser32, PIMAGE_EXPORT_DIRECTORY pExportDir);

// 保证 MyMessageBoxA 在 .shell 置顶
#pragma code_seg(".shell")

void MyMessageBoxA(PBYTE pUser32) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pUser32;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pUser32 + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pUser32 + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PBYTE pMessageBoxA = GetMessageBoxA(pUser32, pExportDir);
    if (pMessageBoxA != NULL) {
        char text[] = { '\0' };
        ((int(*)(...))pMessageBoxA)(0, text, text, MB_ICONINFORMATION);
    }
}

PBYTE GetMessageBoxA(PBYTE pUser32, PIMAGE_EXPORT_DIRECTORY pExportDir) {
    PDWORD pFunctions = (PDWORD)(pUser32 + pExportDir->AddressOfFunctions);
    PDWORD pNames = (PDWORD)(pUser32 + pExportDir->AddressOfNames);
    PWORD pOrdinals = (PWORD)(pUser32 + pExportDir->AddressOfNameOrdinals);
    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
        PBYTE pFuncName = pUser32 + pNames[i];
        if (*pFuncName == 'M' && *(pFuncName + 1) == 'e' && *(pFuncName + 10) == 'A') {
            return pUser32 + pFunctions[(WORD)pOrdinals[i]];
        }
    }
    return NULL;
}

#pragma code_seg(".text")

int main() {
    MyMessageBoxA((PBYTE)LoadLibraryA("user32"));
}
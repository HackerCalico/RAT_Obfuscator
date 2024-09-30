#include <iostream>
#include <windows.h>

/*
* ⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️
* 1.Release x64
* 2.C/C++
* 常规: SDL检查(否)
* 优化: 优化(已禁用)
* 代码生成: 运行库(多线程)、安全检查(禁用安全检查)
* 3.链接器
* 清单文件: 生成清单(否)
* 调试: 生成调试信息(否)
*/

using namespace std;

#pragma code_seg(".shell")

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

#pragma code_seg(".func")

void ExecuteCmd$$(char* commandPara, int commandParaLength, char** pOutputData, int* pOutputDataLength, PVOID specialParaList[]) {
    *pOutputData = (char*)malloc(130);
    sprintf_s(*pOutputData, 130, "%s", "[-] CMD Failed.");
    *pOutputDataLength = 15;

    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return;
    }

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    if (!CreateProcessA(NULL, commandPara, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return;
    }
    CloseHandle(hWrite);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    sprintf_s(*pOutputData, 130, "%s", "[+] Run Successful.\n");
    *pOutputDataLength = 20;
    DWORD currentReadLength;
    do {
        ReadFile(hRead, *pOutputData + *pOutputDataLength, 100, &currentReadLength, NULL);
        *pOutputDataLength += currentReadLength;
        *pOutputData = (char*)realloc(*pOutputData, *pOutputDataLength + 100);
    } while (currentReadLength != 0);

    CloseHandle(hRead);
}

// 占位
volatile void Placeholding() {
    volatile char placeholding1[] = { '\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0' };
    volatile char placeholding2[] = { '\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0','\0' };
}

#pragma code_seg(".text")

int main() {
    MyMessageBoxA((PBYTE)LoadLibraryA("user32"));

    char* commandPara = (char*)"cmd /c tasklist";
    int commandParaLength = strlen(commandPara) + 1;
    char* outputData;
    int outputDataLength = 0;
    PVOID specialParaList[] = { NULL };
    ExecuteCmd$$(commandPara, commandParaLength, &outputData, &outputDataLength, NULL);
    if (outputDataLength > 0) {
        *(outputData + outputDataLength) = '\0';
        cout << outputData << endl;
    }

    // 防止占位消失
    int temp = 0;
    if (temp) {
        Placeholding();
    }
}
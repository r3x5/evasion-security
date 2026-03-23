
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
#define NEW_STREAM L":Broker"

BOOL DeleteSelf() {

    WCHAR path[MAX_PATH * 2];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    FILE_DISPOSITION_INFO disp;
    PFILE_RENAME_INFO renameInfo = NULL;

    const wchar_t streamName[] = NEW_STREAM;

    SIZE_T nameSize = sizeof(streamName) - sizeof(wchar_t);
    SIZE_T structSize = sizeof(FILE_RENAME_INFO) + nameSize;

    HANDLE heap = GetProcessHeap();

    renameInfo = HeapAlloc(heap, HEAP_ZERO_MEMORY, structSize);
    if (!renameInfo)
        return FALSE;

    renameInfo->FileNameLength = nameSize;
    memcpy(renameInfo->FileName, streamName, nameSize);

    disp.DeleteFile = TRUE;

    if (!GetModuleFileNameW(NULL, path, ARRAYSIZE(path)))
        goto FAIL;

    hFile = CreateFileW(path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto FAIL;

    if (!SetFileInformationByHandle(hFile, FileRenameInfo, renameInfo, structSize))
        goto FAIL;

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    hFile = CreateFileW(path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            HeapFree(heap, 0, renameInfo);
            return TRUE;
        }
        goto FAIL;
    }

    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &disp, sizeof(disp)))
        goto FAIL;

    CloseHandle(hFile);
    HeapFree(heap, 0, renameInfo);

    printf("[+] Deleting...\n");

    return TRUE;

FAIL:

    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    if (renameInfo)
        HeapFree(heap, 0, renameInfo);

    return FALSE;
}

int main() {

    if (!DeleteSelf()) {
        return -1;
    }
    printf("[+] Successfully deleted\n");
    return 0;
}

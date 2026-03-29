#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define _CRT_SECURE_NO_WARNINGS

typedef BOOL(*CheckFunc)();

typedef struct {
    const char* name;
    CheckFunc func;
    int weight;
} CheckItem;

BOOL CheckBehaviorConsistency() {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char filePath[MAX_PATH];
    sprintf_s(filePath, MAX_PATH, "%s%llu.tmp", tempPath, GetTickCount64());

    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 4096, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return FALSE;
    }

    char* pView = (char*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pView) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }

    memset(pView, 0x11, 256);
    pView[0] = 'B';

    FlushViewOfFile(pView, 256);
    FlushFileBuffers(hFile);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

    char readBuffer[1];
    DWORD bytesRead;
    ReadFile(hFile, readBuffer, 1, &bytesRead, NULL);

    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);
    DeleteFileA(filePath);
        
    return (readBuffer[0] == 'B');
}

BOOL DelayExecution() {
    ULONGLONG start = GetTickCount64();

    DWORD delay = (rand() % 3000) + 4000;
    Sleep(delay);

    ULONGLONG end = GetTickCount64();
    ULONGLONG elapsed = end - start;

    if (elapsed < delay * 0.8) {
        return FALSE;
    }
    return TRUE;
}

BOOL CheckFolders() {
    const wchar_t* folders[] = {
        L"Adobe", L"Google", L"Java", L"Rockstar Games", L"Steam", L"Mozilla Firefox", L"Creative", L"Microsoft Office",
        L"Intel", L"Microsoft Office 15", L"Microsoft Update Health Tools", L"NVIDIA", L"NVIDIA Corporation",
        L"ModifiableWindowsApps", L"Microsoft SQL Server", L"Autodesk", L"EA Games", L"Ubisoft", L"Origin", L"Epic Games",
        L"Oracle", L"MySQL", L"Electronic Arts", L"Chaos Group", L"Blender", L"WinRAR", L"Notepad++", NULL
    };

    int hits = 0;

    for (int i = 0; folders[i] != NULL; i++) {
        wchar_t path[MAX_PATH];
        swprintf_s(path, MAX_PATH, L"C:\\Program Files\\%ls", folders[i]);

        DWORD attr = GetFileAttributesW(path);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            wprintf(L"      [+] Found Folder: %ls\n", folders[i]);
            hits++;
        }
    }
    wprintf(L"[*] Folder Total hits: %d\n", hits);
    return hits >= 3;
}

BOOL CheckProcesses() {
    const wchar_t* targets[] = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"iexplore.exe",
        L"winword.exe", L"excel.exe", L"powerpnt.exe",
        L"outlook.exe", L"onenote.exe",
        L"teams.exe", L"ms-teams.exe",
        L"wps.exe", L"wpp.exe", L"et.exe",
        L"notepad++.exe", L"code.exe",
        L"wt.exe",
        L"7zFM.exe", L"7z.exe", L"WinRAR.exe",
        L"QQ.exe", L"WeChat.exe", L"DingTalk.exe", L"Slack.exe", L"Zoom.exe",
        L"Dropbox.exe", L"OneDrive.exe", L"OneDriveStandaloneUpdater.exe", L"GoogleDriveFS.exe",
        L"vmware.exe", L"vmware-vmx.exe", L"VirtualBox.exe",
        L"java.exe", L"javaw.exe", L"node.exe", L"python.exe",
        L"git.exe", L"git-bash.exe",
        L"steam.exe", L"EpicGamesLauncher.exe",
        L"Everything.exe",
        L"AnyDesk.exe", L"TeamViewer.exe",
        L"AdobeAcroRd32.exe", L"Acrobat.exe",
        L"Photoshop.exe", L"Illustrator.exe",
        L"Thunder.exe",
        L"obs64.exe",
        NULL
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int hits = 0;
    int matched[100];
    ZeroMemory(matched, sizeof(matched));

    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; targets[i] != NULL; i++) {
                if (matched[i]) continue;
                if (_wcsicmp(pe.szExeFile, targets[i]) == 0) {
                    matched[i] = 1;
                    hits++;
                    wprintf(L"[+]     Found Process: %ls\n", pe.szExeFile);
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    printf("[*] Process Total hits: %d\n", hits);
    return hits >= 2;
}

BOOL IsRecentChange(FILETIME* fileTime, int days) {
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);

    ULARGE_INTEGER ftFile, ftNow;
    ftFile.LowPart = fileTime->dwLowDateTime;
    ftFile.HighPart = fileTime->dwHighDateTime;

    ftNow.LowPart = currentTime.dwLowDateTime;
    ftNow.HighPart = currentTime.dwHighDateTime;

    // 1 day = 24 * 60 * 60 * 10^7 (100ns units)
    ULONGLONG diff = ftNow.QuadPart - ftFile.QuadPart;
    ULONGLONG threshold = (ULONGLONG)days * 24 * 60 * 60 * 10000000ULL;

    return diff <= threshold;
}

BOOL ScanDirectory(const char* path, int days, int* count, int limit) {
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*.*", path);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", path, findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectory(fullPath, days, count, limit);
        }
        else {
            if (IsRecentChange(&findData.ftLastWriteTime, days) ||
                IsRecentChange(&findData.ftCreationTime, days)) {
                (*count)++;
                if (*count >= limit) {
                    FindClose(hFind);
                    return TRUE;
                }
            }
        }

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return FALSE;
}

BOOL CheckRecentChanges() {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA("C:\\Users\\*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    int count = 0;

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(findData.cFileName, ".") != 0 &&
            strcmp(findData.cFileName, "..") != 0) {

            char userPath[MAX_PATH];
            snprintf(userPath, MAX_PATH, "C:\\Users\\%s", findData.cFileName);

            ScanDirectory(userPath, 7, &count, 10);
            if (count > 0) {
                break;
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return count > 0;
}

BOOL CheckBrowserSessions() {
    char userPath[MAX_PATH];
    char currentUser[256];
    DWORD size = sizeof(currentUser);

    if (!GetUserNameA(currentUser, &size)) {
        return FALSE;
    }

    sprintf_s(userPath, MAX_PATH, "C:\\Users\\%s", currentUser);

    int score = 0;

    const char* chromiumPaths[] = {
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",
        NULL
    };

    for (int i = 0; chromiumPaths[i]; i++) {
        char fullPath[MAX_PATH];
        sprintf_s(fullPath, MAX_PATH, "%s%s", userPath, chromiumPaths[i]);

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(fullPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            ULONGLONG size = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

            if (size > 100 * 1024) {
                score += 2;
            }
            else {
                score += 1;
            }
            FindClose(hFind);
        }
    }

    char firefoxBase[MAX_PATH];
    sprintf_s(firefoxBase, MAX_PATH, "%s\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\*", userPath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(firefoxBase, &fd);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

            char placesPath[MAX_PATH];
            sprintf_s(placesPath, MAX_PATH,
                "%s\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\%s\\places.sqlite",
                userPath, fd.cFileName);

            WIN32_FIND_DATAA fd2;
            HANDLE hFind2 = FindFirstFileA(placesPath, &fd2);
            if (hFind2 != INVALID_HANDLE_VALUE) {
                ULONGLONG size = ((ULONGLONG)fd2.nFileSizeHigh << 32) | fd2.nFileSizeLow;

                if (size > 100 * 1024) {
                    score += 2;
                }
                else {
                    score += 1;
                }
                FindClose(hFind2);
            }

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }
    return score >= 2;
}

BOOL CheckPSHistory() {
    char userPath[MAX_PATH];
    char currentUser[256];
    DWORD size = sizeof(currentUser);

    if (!GetUserNameA(currentUser, &size)) {
        return FALSE;
    }

    sprintf_s(userPath, MAX_PATH, "C:\\Users\\%s", currentUser);

    char psPath[MAX_PATH];
    sprintf_s(psPath, MAX_PATH,
        "%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        userPath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(psPath, &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    ULONGLONG fileSize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

    if (fileSize > 5 * 1024) {
        FindClose(hFind);
        return TRUE;
    }

    FindClose(hFind);
    return FALSE;
}

int RunChecks(CheckItem* items) {
    int score = 0;
    int maxScore = 0;

    for (int i = 0; items[i].name != NULL; i++) {
        maxScore += items[i].weight;
        BOOL result = items[i].func();

        if (result) {
            score += items[i].weight;
            printf("[+] %s: PASS\n", items[i].name);
        }
        else {
            printf("[-] %s: FAIL\n", items[i].name);
        }
    }
    return (score * 100) / maxScore;
}

int IsRealEnvirement() {
    CheckItem checks[] = {
        {"DelayExecution", DelayExecution, 2},
        {"CheckBehaviorConsistency", CheckBehaviorConsistency, 2},
        {"CheckRecentChanges", CheckRecentChanges, 3},
        {"CheckPSHistory", CheckPSHistory, 1},
        {"CheckFolders", CheckFolders, 3},
        {"CheckProcesses", CheckProcesses, 2},
        {"CheckBrowserSessions", CheckBrowserSessions, 2},
        {NULL, NULL, 0}
    };

    int score = RunChecks(checks);

    printf("Final Score: %d%%\n", score);

    if (score >= 60) {
        printf("[+] Real environment\n");
    }
    else {
        printf("[!] Suspicious environment\n");
    }

    printf("[*]\n");
    printf("[*] Exit...\n");
    printf("[*]\n");

    return score >= 60;
}
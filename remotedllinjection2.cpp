#define _UNICODE
#define UNICODE

#include <iostream>
#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <tchar.h>

using namespace std;

#define TARGET_PROCESS _T("Notepad.exe")

DWORD GetProcessIDByProcessName(LPCTSTR ProcessName, HANDLE* hProcess) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        _tprintf(_T("[!] Error in Snapshot: %lu\n"), GetLastError());
        return 0;
    }

    DWORD PID = 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcscmp(ProcessName, pe.szExeFile) == 0) {
                PID = pe.th32ProcessID;
                *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
                if (*hProcess == NULL) {
                    _tprintf(_T("[!] Error in Opening Process: %lu\n"), GetLastError());
                    return 0;
                }
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return PID;
}

BOOL InjectDLLtoRemoteProcess(DWORD dwProcessId, LPCTSTR DllName) {
    BOOL bState = TRUE;
    HMODULE hKernel32;
    LPVOID funcaddr;
    LPVOID address;
    DWORD dwSizeToWrite = (lstrlen(DllName) + 1) * sizeof(TCHAR);
    SIZE_T lpNumberOfBytesWritten = 0;
    HANDLE hThread = NULL;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    if (hProcess == NULL) {
        _tprintf(_T("[!] Error in Opening Process: %lu\n"), GetLastError());
        return FALSE;
    }

    hKernel32 = GetModuleHandle(_T("kernel32.dll"));
    funcaddr = GetProcAddress(hKernel32, "LoadLibraryW");
    if (funcaddr == NULL) {
        _tprintf(_T("[!] Error in function address: %lu\n"), GetLastError());
        bState = FALSE;
        goto _cleanup;
    }

    address = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (address == NULL) {
        _tprintf(_T("[!] Error in memory allocation: %lu\n"), GetLastError());
        bState = FALSE;
        goto _cleanup;
    }

    if (!WriteProcessMemory(hProcess, address, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
        _tprintf(_T("[!] Error in Write DLL to Process Memory: %lu\n"), GetLastError());
        bState = FALSE;
        goto _cleanup;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)funcaddr, address, 0, NULL);
    if (hThread == NULL) {
        _tprintf(_T("[!] Error in Creating Remote Thread: %lu\n"), GetLastError());
        bState = FALSE;
        goto _cleanup;
    }

_cleanup:
    CloseHandle(hProcess);
    if (hThread != NULL)
        CloseHandle(hThread);

    return bState;
}

int _tmain(int argc, TCHAR* argv[]) {
    DWORD pid;
    BOOL success;
    LPCTSTR DLLNAME = _T("C:\\Users\\Msi\\source\\repos\\mydll\\x64\\Debug\\mydll.dll");
    HANDLE hProcess = NULL;

    pid = GetProcessIDByProcessName(TARGET_PROCESS, &hProcess);
    if (pid == 0) {
        _tprintf(_T("[!] Error in finding TARGET Process\n"));
        return -1;
    }

    success = InjectDLLtoRemoteProcess(pid, DLLNAME);
    if (!success) {
        _tprintf(_T("[!] Error injecting DLL into remote process\n"));
        CloseHandle(hProcess);
        return -1;
    }

    _tprintf(_T("[+] Successfully Injected DLL to Remote Process [+]\n"));

    CloseHandle(hProcess);
    return 0;
}

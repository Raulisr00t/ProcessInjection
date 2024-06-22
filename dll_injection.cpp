#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <tchar.h>
#include <Psapi.h>

using namespace std;

DWORD GetProcessId(LPCTSTR processname) {
    DWORD pid = 0;
    HANDLE hSnapshot;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cerr << "Cannot create snapshot of the process list." << endl;
        cout << "Error is: " << GetLastError() << endl;
        return 0;
    }

    if (Process32First(hSnapshot, &entry)) {
        do {
            if (_tcscmp(entry.szExeFile, processname) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &entry));
    }
    else {
        cerr << "[!] Cannot iterate over processes." << endl;
        cout << "[!] Error: " << GetLastError() << endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "[!] Usage: <dll_injection.exe> <DLL path> <ProcessName>" << endl;
        return 1;
    }

    string processname_str = argv[2];

#ifdef UNICODE
    wstring wprocessname(processname_str.begin(), processname_str.end());
    LPCTSTR processname = wprocessname.c_str();
#else
    LPCTSTR processname = processname_str.c_str();
#endif

    DWORD pid = GetProcessId(processname);
    if (pid == 0) {
        cerr << "Failed to find process: " << processname_str << endl;
        return 1;
    }

    cout << "Process ID: " << pid << endl;

    HMODULE loader = LoadLibraryA(argv[1]);
    if (loader == NULL) {
        cerr << "[!] Error loading the library" << endl;
        cout << "[!] Error is: " << GetLastError() << endl;
        if (GetLastError() == ERROR_DLL_NOT_FOUND) {
            cerr << "[-] DLL Not Found in your system" << endl;
        }
        return 1;
    }
    cout << "[+] DLL loaded successfully" << endl;

    if (!FreeLibrary(loader)) {
        cerr << "[!] Error freeing the library" << endl;
        cout << "[!] Error is: " << GetLastError() << endl;
        return 1;
    }
    cout << "[+] DLL freed successfully" << endl;

    return 0;
}

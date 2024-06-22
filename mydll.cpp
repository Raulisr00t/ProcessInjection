#include "pch.h"
#include <stdio.h>
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {   
        BOOL hProcess;
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        wchar_t processName[] = L"calc.exe"; // write your own process
        hProcess = CreateProcess(NULL, processName, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

        if (hProcess == NULL) {
            printf("[!] Error starting the process\n");
            printf("[!] Error is: %lu\n", GetLastError());
            return FALSE;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

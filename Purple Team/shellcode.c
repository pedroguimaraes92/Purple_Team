// shellcode.c
#include <windows.h>
#include <stdio.h>
#include "syscalls/syscalls.h"

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

DWORD WINAPI MainThread(LPVOID param) {
    HANDLE hProcess = NULL;
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    DWORD pid = *(DWORD*)param;  // Espera o PID como argumento

    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (PVOID)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (status >= 0 && hProcess != NULL) {
        // Sucesso!
        MessageBoxA(NULL, "NtOpenProcess SUCCESS", "Shellcode", MB_OK);
        CloseHandle(hProcess);
    } else {
        MessageBoxA(NULL, "NtOpenProcess FAILED", "Shellcode", MB_OK);
    }

    return 0;
}

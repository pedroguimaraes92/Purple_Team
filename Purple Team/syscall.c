#include <windows.h>
#include <stdio.h>

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

int main() {
    DWORD pid = 1234; // troque pelo PID real do notepad.exe
    HANDLE hProcess = NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

    CLIENT_ID cid;
    cid.UniqueProcess = (PVOID)(ULONG_PTR)pid;
    cid.UniqueThread = NULL;

    NTSTATUS status;

    // Exemplo usando syscall direta
    __asm {
        mov r10, rcx                 // por convenção do Windows x64
        mov eax, 0x26                // Syscall ID hipotético de NtOpenProcess
        syscall
        mov status, eax
        mov hProcess, rax
    }

    printf("Status: 0x%X\n", status);
    if (hProcess)
        printf("Handle: %p\n", hProcess);
    else
        printf("Falha ao abrir processo\n");

    return 0;
}

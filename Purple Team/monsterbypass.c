#include <stdio.h>
#include <windows.h>

// Tamanho máximo do nome do processo
#define MAX_NAME 260

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

// A estrutura SYSTEM_PROCESS_INFORMATION é bem maior, mas precisamos só do começo
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    // ... tem mais coisa, mas não precisamos
} SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define SystemProcessInformation 5

int main() {
    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        printf("Falha ao obter NtQuerySystemInformation.\n");
        return 1;
    }

    ULONG bufferSize = 0x10000;
    PBYTE buffer = NULL;
    NTSTATUS status;
    ULONG returnLength = 0;

    do {
        buffer = (PBYTE)malloc(bufferSize);
        if (!buffer) {
            printf("Falha ao alocar memória.\n");
            return 1;
        }

        status = NtQuerySystemInformation(SystemProcessInformation,
                                          buffer, bufferSize, &returnLength);

        if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            free(buffer);
            bufferSize *= 2;
        } else if (status < 0) {
            printf("Erro ao chamar NtQuerySystemInformation: 0x%X\n", status);
            free(buffer);
            return 1;
        }
    } while (status == 0xC0000004);

    // Percorrer a lista
    PBYTE ptr = buffer;
    DWORD pid = 0;
    WCHAR targetName[] = L"notepad.exe";

    while (1) {
        SYSTEM_PROCESS_INFORMATION* info = (SYSTEM_PROCESS_INFORMATION*)ptr;

        if (info->ImageName.Buffer) {
            // Comparar nomes
            if (_wcsicmp(info->ImageName.Buffer, targetName) == 0) {
                pid = (DWORD)(ULONG_PTR)info->UniqueProcessId;
                break;
            }
        }

        if (info->NextEntryOffset == 0)
            break;

        ptr += info->NextEntryOffset;
    }

    free(buffer);

    if (pid == 0) {
        printf("Processo não encontrado.\n");
        return 1;
    }

    printf("PID encontrado: %lu\n", pid);

    // Agora podemos abrir com OpenProcess
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess) {
        printf("Processo aberto! Handle: %p\n", hProcess);
        CloseHandle(hProcess);
    } else {
        printf("Falha ao abrir o processo.\n");
    }

    return 0;
}

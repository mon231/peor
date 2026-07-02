#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define NOP_SLED_MAX_OFFSET 1024
#define NOP_BYTE            ((BYTE)0x90)

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: test_loader <shellcode_path>\n");
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "open failed (err %lu): %s\n", GetLastError(), argv[1]);
        return 1;
    }

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        fprintf(stderr, "bad file size\n");
        CloseHandle(hFile);
        return 1;
    }

    srand(GetTickCount());
    /* Keep nop_offset 16-byte aligned so the PE image (which starts at
       mem + nop_offset + prefix_len, where prefix_len is 16-aligned) is
       always 16-byte aligned for MOVDQA/MOVAPS instructions. */
    DWORD nop_offset = (1 + (DWORD)(rand() % (NOP_SLED_MAX_OFFSET / 16))) * 16;

    void* mem = VirtualAlloc(NULL, size + NOP_SLED_MAX_OFFSET,
                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "VirtualAlloc failed (err %lu)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    memset(mem, NOP_BYTE, nop_offset);
    BYTE* shellcode_start = (BYTE*)mem + nop_offset;

    DWORD nread = 0;
    if (!ReadFile(hFile, shellcode_start, size, &nread, NULL) || nread != size) {
        fprintf(stderr, "read failed (err %lu)\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    int exit_code = ((int(*)(void))mem)();
    printf("exit code: %d\n", exit_code);

    VirtualFree(mem, 0, MEM_RELEASE);
    return exit_code;
}

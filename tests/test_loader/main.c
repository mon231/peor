#include <windows.h>
#include <stdio.h>

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

    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!mem) {
        fprintf(stderr, "VirtualAlloc failed (err %lu)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    DWORD nread = 0;
    if (!ReadFile(hFile, mem, size, &nread, NULL) || nread != size) {
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

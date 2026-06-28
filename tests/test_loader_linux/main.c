/*
 * Linux test_loader — loads a shellcode file, places it at a random offset
 * in an executable mapping (NOP sled), calls it, and prints its return value
 * to stdout so callers can read the full int (Linux exit codes are only 8 bits).
 *
 * Used for testing PE-to-shellcode output on Linux (e.g. MinGW cross-compiled PEs
 * without Windows API imports).
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define NOP_SLED_MAX_OFFSET 1024
#define NOP_BYTE            ((uint8_t)0x90)

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: test_loader_linux <shellcode_path>\n");
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        fprintf(stderr, "bad file size\n");
        close(fd);
        return 1;
    }
    size_t size = (size_t)st.st_size;

    /* Keep nop_offset 16-byte aligned so the PE image is always 16-byte aligned
       for MOVDQA/MOVAPS instructions in the shellcode. */
    srand((unsigned)getpid());
    size_t nop_offset = (size_t)(1 + (rand() % (NOP_SLED_MAX_OFFSET / 16))) * 16;
    size_t total      = size + NOP_SLED_MAX_OFFSET + 4096;

    uint8_t *mem = (uint8_t *)mmap(NULL, total,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    memset(mem, NOP_BYTE, nop_offset);
    uint8_t *shellcode_start = mem + nop_offset;

    ssize_t nread = read(fd, shellcode_start, size);
    close(fd);
    if (nread != (ssize_t)size) {
        fprintf(stderr, "read failed\n");
        munmap(mem, total);
        return 1;
    }

    if (mprotect(mem, total, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        munmap(mem, total);
        return 1;
    }

    /* The shellcode finds dlopen/dlsym by itself via /proc/self/maps + ELF parsing.
       No arguments needed from the loader. */
#ifdef __i386__
    /* On x86, the shellcode chain leaves EBX=PE_base, ESI=NT_hdrs, EDI=reloc_delta
     * on return (they're set by the resolver chain and preserved by the cdecl OEP).
     * List them as clobbers so GCC saves/restores them around this call. */
    int result;
    void *_fn = (void *)mem;
    __asm__ volatile(
        "call *%1"
        : "=a"(result)
        : "m"(_fn)
        : "ebx", "ecx", "edx", "esi", "edi", "memory", "cc"
    );
#else
    int result = ((int (*)(void))mem)();
#endif

    munmap(mem, total);

    /* Print full int value so callers bypass the 8-bit Linux exit code limit. */
    fprintf(stdout, "%d\n", result);
    fflush(stdout);
    return 0;
}

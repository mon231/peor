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

    /* Declare as volatile so GCC always reloads mem/total from the stack slot
     * after the shellcode call (avoids caching them in caller-saved regs that
     * the shellcode may clobber). */
    uint8_t * volatile mem = (uint8_t *)mmap(NULL, total,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile size_t vtotal = total;
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
       No arguments needed from the loader.  The x86-32 loader is built with
       -no-pie so PLT stubs use absolute addresses instead of [ebx+N]; this
       makes the relocs-resolver's EBX=PE_base side-effect harmless. */
    /* The shellcode violates the SysV callee-saved ABI: the chain hands off
       state in callee-saved registers (e.g. the x64 relocs resolver sets
       RBX = PE base and falls through instead of returning).  Save/restore
       all callee-saved registers around the call so this main() can return
       its own exit status instead of the clobbered one. */
#ifdef __x86_64__
    int result;
    asm volatile(
        "push %%rbx\n\t"
        "push %%rbp\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"
        "call *%1\n\t"
        "pop %%r15\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbp\n\t"
        "pop %%rbx\n\t"
        : "=a"(result)
        : "r"(mem)
        : "memory", "cc");
#else
    int result;
    asm volatile(
        "push %%ebx\n\t"
        "push %%esi\n\t"
        "push %%edi\n\t"
        "push %%ebp\n\t"
        "call *%1\n\t"
        "pop %%ebp\n\t"
        "pop %%edi\n\t"
        "pop %%esi\n\t"
        "pop %%ebx\n\t"
        : "=a"(result)
        : "r"(mem)
        : "memory", "cc");
#endif

    munmap(mem, vtotal);

    /* Print full int value so callers bypass the 8-bit Linux exit code limit. */
    fprintf(stdout, "%d\n", result);
    fflush(stdout);
    return 0;
}

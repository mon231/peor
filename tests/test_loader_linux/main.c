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
#define NOP_BYTE            ((uint8_t)0x90)   /* x86/x64 single-byte NOP */

/* ARM64 has no 1-byte NOP (fixed 4-byte instruction width) - fill the sled with
 * the real 4-byte NOP encoding (nop_offset is always 16-byte aligned, so always
 * a whole number of 4-byte instruction slots) instead of a repeating byte. */
#if defined(__aarch64__)
static const uint8_t NOP_WORD_ARM64[4] = {0x1F, 0x20, 0x03, 0xD5};
static void fill_nop_sled(uint8_t *mem, size_t nop_offset) {
    for (size_t i = 0; i < nop_offset; i += 4) {
        mem[i + 0] = NOP_WORD_ARM64[0];
        mem[i + 1] = NOP_WORD_ARM64[1];
        mem[i + 2] = NOP_WORD_ARM64[2];
        mem[i + 3] = NOP_WORD_ARM64[3];
    }
}
#endif

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

#if defined(__aarch64__)
    /* AArch64 PIC (adrp/ldr, which any non-trivial compiled PE's own code uses
       throughout to reach its own .rdata/IAT) is page-granular: it only computes
       correct addresses when the *embedded PE's* runtime base is congruent to its
       link-time ImageBase modulo the page size - i.e. page-aligned. mmap() below
       always returns a page-aligned address, so nop_offset must stay exactly 0
       (peor's _PLATFORM_LINUX_ARM64 chain pads its stub prefix to a page-size
       multiple - see peor/_chain_builder.py's 'pe_align': 4096 - so the embedded
       PE itself lands on the next page boundary after this zero offset).
       x86/x64 have no such requirement (RIP-relative LEA is byte-granular), which
       is why only ARM64 pins this to 0 instead of randomizing within the sled. */
    size_t nop_offset = 0;
#else
    /* Keep nop_offset 16-byte aligned so the PE image is always 16-byte aligned
       for MOVDQA/MOVAPS instructions in the shellcode. */
    srand((unsigned)getpid());
    size_t nop_offset = (size_t)(1 + (rand() % (NOP_SLED_MAX_OFFSET / 16))) * 16;
#endif
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

#if defined(__aarch64__)
    fill_nop_sled(mem, nop_offset);
#else
    memset(mem, NOP_BYTE, nop_offset);
#endif
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
    int result = ((int (*)(void))mem)();

    munmap(mem, vtotal);

    /* Print full int value so callers bypass the 8-bit Linux exit code limit. */
    fprintf(stdout, "%d\n", result);
    fflush(stdout);
    return 0;
}

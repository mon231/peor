/*
 * Linux CRT test: uses libc.so.6 imports (strlen, malloc, free) via the Linux
 * import resolver. Verifies that complex CRT imports work in the Linux chain.
 * Returns 73 on success.
 *
 * Compile (x64):
 *   Build libc.def and libpthread.def, then:
 *   x86_64-w64-mingw32-gcc -nostartfiles -nodefaultlibs -fno-unwind-tables \
 *     -fno-asynchronous-unwind-tables \
 *     main.c liblibc.a -Wl,-e,main -Wl,--subsystem,posix -o 03_linux_crt.pe
 */

#define LINUX_CRT_RETURN_CODE 73

#ifdef _WIN64
typedef unsigned long long size_t;
/* x64: libc functions use SysV AMD64 ABI (RDI/RSI/RDX), not Windows MS ABI */
#define SYSV_ABI __attribute__((sysv_abi))
#else
typedef unsigned int size_t;
#define SYSV_ABI
#endif

/* Imported from libc.so.6 via the Linux import resolver */
extern SYSV_ABI size_t strlen(const char *s);
extern SYSV_ABI void  *malloc(size_t n);
extern SYSV_ABI void   free(void *p);
extern SYSV_ABI void  *memcpy(void *dst, const void *src, size_t n);
extern SYSV_ABI int    strncmp(const char *a, const char *b, size_t n);

SYSV_ABI int main(void) {
    static const char msg[] = "PEOR_LINUX_CRT_TEST";
    size_t expected_len = sizeof(msg) - 1;   /* 19 */
    size_t actual_len = strlen(msg);
    if (actual_len != expected_len)
        return 1;

    char *buf = (char *)malloc(actual_len + 1);
    if (!buf)
        return 2;
    memcpy(buf, msg, actual_len + 1);
    size_t copy_len = strlen(buf);
    if (strncmp(buf, msg, actual_len) != 0)
        return 4;
    free(buf);
    if (copy_len != expected_len)
        return 3;

    return LINUX_CRT_RETURN_CODE;
}

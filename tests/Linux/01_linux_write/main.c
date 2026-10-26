/*
 * Linux write test PE - imports write() from libc.so.6, prints "PEOR\n".
 * Supports both x64 (PE32+, amd64) and x86 (PE32, IA-32).
 *
 * Compiled as a Windows-format PE (MinGW) targeting Linux via peor's Linux shellcode chain.
 * On x64 the write() import uses __attribute__((sysv_abi)) so GCC emits SysV AMD64 argument
 * passing (RDI/RSI/RDX) to match what dlsym returns.  x86 cdecl already matches Linux IA-32.
 *
 * Compile (x64):
 *   echo "LIBRARY libc.so.6" > libc.so.6.def && echo "EXPORTS" >> libc.so.6.def && echo "write" >> libc.so.6.def
 *   x86_64-w64-mingw32-dlltool -d libc.so.6.def -l liblibc_import.a
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,main -Wl,--subsystem,posix \
 *     main.c liblibc_import.a -o 01_linux_write.exe
 *
 * Compile (x86):
 *   echo "LIBRARY libc.so.6" > libc.so.6.def && echo "EXPORTS" >> libc.so.6.def && echo "write" >> libc.so.6.def
 *   i686-w64-mingw32-dlltool -d libc.so.6.def -l liblibc_import32.a
 *   i686-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,main -Wl,--subsystem,posix \
 *     main.c liblibc_import32.a -o 01_linux_write_x86.exe
 */

#ifdef _WIN64
typedef long long          ssize_t;
typedef unsigned long long size_t;
/* x64: write() uses SysV AMD64 ABI (RDI/RSI/RDX), not Windows MS ABI */
extern __declspec(dllimport) __attribute__((sysv_abi))
    ssize_t write(int fd, const void *buf, size_t count);
#else
typedef int          ssize_t;
typedef unsigned int size_t;
/* x86: cdecl matches Linux IA-32 ABI (stack args), no attribute needed */
extern __declspec(dllimport) ssize_t write(int fd, const void *buf, size_t count);
#endif

#define STDOUT_FD 1

#ifdef _WIN64
__attribute__((sysv_abi))
#endif
int main(void) {
    static const char msg[] = "PEOR\n";
    write(STDOUT_FD, msg, sizeof(msg) - 1);
    return 0;
}

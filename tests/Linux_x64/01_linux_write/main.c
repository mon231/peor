/*
 * Linux write test PE - imports write() from libc.so.6
 * Compiled as a Windows-format PE (MinGW) but targets Linux via peor's Linux shellcode chain.
 *
 * Uses __attribute__((sysv_abi)) throughout so calls to write() use the
 * Linux System V AMD64 ABI (RDI/RSI/RDX args), not the Windows MSABI (RCX/RDX/R8 args).
 * This matches what dlsym returns (a native Linux libc function).
 *
 * Compile:
 *   # Create import library that makes GCC emit PE imports from "libc.so.6"
 *   echo "LIBRARY libc.so.6" > libc.so.6.def
 *   echo "EXPORTS" >> libc.so.6.def
 *   echo "write" >> libc.so.6.def
 *   x86_64-w64-mingw32-dlltool -d libc.so.6.def -l liblibc_import.a
 *   # Compile
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,main -Wl,--subsystem,posix \
 *     main.c liblibc_import.a -o 01_linux_write.exe
 */

typedef long long ssize_t;
typedef unsigned long long size_t;

/* write() lives in libc.so.6 on Linux; import it via the PE import table.
   __attribute__((sysv_abi)) ensures GCC emits SysV argument passing (RDI/RSI/RDX)
   instead of the Windows MSABI (RCX/RDX/R8). */
extern __declspec(dllimport) __attribute__((sysv_abi))
    ssize_t write(int fd, const void *buf, size_t count);

/* Entire main uses SysV ABI so internal calls also use SysV. */
__attribute__((sysv_abi)) int main(void) {
    static const char msg[] = "PEOR\n";
    write(1, msg, 5);
    return 0;
}

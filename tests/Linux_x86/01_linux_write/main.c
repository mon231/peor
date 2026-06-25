/*
 * x86 Linux write test PE - imports write() from libc.so.6.
 * Compiled as a PE32 (32-bit) with i686-w64-mingw32-gcc, targeting Linux via peor.
 *
 * For x86 Linux, the default calling convention (cdecl) matches Linux System V
 * IA-32 ABI: args pushed right-to-left on the stack.  No __attribute__ needed.
 *
 * Compile:
 *   echo "LIBRARY libc.so.6" > libc.so.6.def
 *   echo "EXPORTS" >> libc.so.6.def
 *   echo "write" >> libc.so.6.def
 *   i686-w64-mingw32-dlltool -d libc.so.6.def -l liblibc_import32.a
 *   i686-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,main -Wl,--subsystem,posix \
 *     main.c liblibc_import32.a -o 01_linux_write_x86.exe
 */

typedef int          ssize_t;
typedef unsigned int size_t;

extern __declspec(dllimport) ssize_t write(int fd, const void *buf, size_t count);

int main(void) {
    static const char msg[] = "PEOR\n";
    write(1, msg, 5);
    return 0;
}

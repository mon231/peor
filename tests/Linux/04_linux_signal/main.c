/*
 * Linux signal test: installs a SIGUSR1 handler via signal(), raises SIGUSR1,
 * and returns SIGNAL_RETURN_CODE (77) if the handler was called.
 * Supports both x64 (PE32+) and x86 (PE32).
 *
 * Compile (x64):
 *   echo "LIBRARY libc.so.6" > libc.def && echo "EXPORTS" >> libc.def
 *   echo "signal" >> libc.def && echo "raise" >> libc.def
 *   x86_64-w64-mingw32-dlltool -d libc.def -l liblibc_signal.a
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,main -Wl,--subsystem,posix \
 *     main.c liblibc_signal.a -o 04_linux_signal.pe
 *
 * Compile (x86):
 *   i686-w64-mingw32-dlltool -d libc.def -l liblibc_signal32.a
 *   i686-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,_main -Wl,--subsystem,posix \
 *     main.c liblibc_signal32.a -o 04_linux_signal_x86.pe
 */

#define SIGNAL_RETURN_CODE  77
#define SIGNAL_FAIL_CODE     1
#define SIGUSR1             10

#ifdef _WIN64
typedef unsigned long long size_t;
#define SYSV_ABI __attribute__((sysv_abi))
#else
typedef unsigned int size_t;
#define SYSV_ABI
#endif

typedef SYSV_ABI void (*sighandler_t)(int);

/* Imported from libc.so.6 via the Linux import resolver */
extern SYSV_ABI sighandler_t signal(int signum, sighandler_t handler);
extern SYSV_ABI int          raise(int sig);

static int g_handler_called = 0;

static SYSV_ABI void signal_handler(int sig) {
    (void)sig;
    g_handler_called = 1;
}

SYSV_ABI int main(void) {
    signal(SIGUSR1, signal_handler);
    raise(SIGUSR1);
    return g_handler_called ? SIGNAL_RETURN_CODE : SIGNAL_FAIL_CODE;
}

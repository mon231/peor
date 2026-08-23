/*
 * Linux global constructor test: two global objects whose constructors each
 * add to g_counter; main returns GLOBAL_CTOR_RETURN_CODE (99) when the sum is
 * correct, proving that peor's ctors runner fires before main().
 * Supports both x64 (PE32+) and x86 (PE32).
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-g++-posix -fexceptions -nostartfiles -nodefaultlibs \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtbegin.o) \
 *     main.cpp \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtend.o) \
 *     -lgcc_eh -lsupc++ -lgcc \
 *     -Wl,-e,main -Wl,--subsystem,posix -o 05_linux_global_ctor.pe
 *
 * Compile (x86):
 *   i686-w64-mingw32-g++-posix -fexceptions -nostartfiles -nodefaultlibs \
 *     ... same flags ... -Wl,-e,_main -Wl,--subsystem,posix
 */

#define GLOBAL_CTOR_EXPECTED 99
#define GLOBAL_CTOR_RETURN_CODE 99
#define GLOBAL_CTOR_FAIL_CODE    1

static int g_counter = 0;

struct Adder {
    explicit Adder(int n) { g_counter += n; }
};

static Adder g_a(42);
static Adder g_b(57);

extern "C" int main() {
    return (g_counter == GLOBAL_CTOR_EXPECTED) ? GLOBAL_CTOR_RETURN_CODE
                                               : GLOBAL_CTOR_FAIL_CODE;
}

/*
 * Linux C++ exception test.
 * Throws a custom type, catches it, returns CPP_EH_RETURN_CODE (42).
 * Compiled as a Windows PE32+/PE32 with POSIX_CUI (subsystem 7); peor selects the Linux chain.
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-g++-posix -fexceptions -nostartfiles -nodefaultlibs \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtbegin.o) \
 *     main.cpp \
 *     $(x86_64-w64-mingw32-g++-posix -print-file-name=crtend.o) \
 *     -lgcc_eh -lsupc++ -lgcc \
 *     -Wl,-e,main -Wl,--subsystem,posix -o 02_linux_cpp.pe
 */

#define CPP_EH_RETURN_CODE   42
#define CPP_EH_CATCH_ALL_CODE 88

struct PeorLinuxException {
    int code;
};

extern "C" int main() {
    int result = 0;
    try {
        throw PeorLinuxException{CPP_EH_RETURN_CODE};
    } catch (const PeorLinuxException &e) {
        result = e.code;
    } catch (...) {
        result = CPP_EH_CATCH_ALL_CODE;
    }
    return result;
}

/*
 * Windows MinGW DWARF C++ exception test.
 * Compiled with x86_64-w64-mingw32-g++-posix (DWARF-2 exceptions).
 * Throws PeorMinGWException{42}, catches it, returns 42.
 * peor's ctors runner initialises DWARF EH frames before WinMain runs.
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-g++-posix -fexceptions -nostartfiles -nodefaultlibs
 *     peor_crtbegin.o freestanding.o main.cpp
 *     -lgcc_eh -lsupc++ -lgcc -Wl,-e,WinMain -Wl,--subsystem,windows
 *     peor_crtend.o -o 17_mingw_cpp.exe
 */

#define MINGW_CPP_RETURN_CODE 42

struct PeorMinGWException { int code; };

extern "C" int WinMain(void *, void *, void *, int) {
    int result = 0;
    try {
        throw PeorMinGWException{MINGW_CPP_RETURN_CODE};
    } catch (PeorMinGWException &e) {
        result = e.code;
    } catch (...) {
        result = 88;
    }
    return result;
}

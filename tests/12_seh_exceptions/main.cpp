// test_12: typed C++ exceptions compiled with /EHa (SEH-integrated exception handling).
// With /EHa the compiler integrates C++ exceptions with Windows SEH; the same
// RtlPcToFileHeader / GetModuleHandleExW hook must still fix ImageBase resolution
// in shellcode context.
// Returns 123 if typed catch fires, 456 if catch(...) fires, 789 if no catch.

#include <windows.h>

class SehModeException final {
public:
    explicit SehModeException(int code) : _code(code) {}
    int code() const { return _code; }
private:
    int _code;
};

static int run_test() {
    try {
        throw SehModeException{123};
    }
    catch (const SehModeException& e) {
        return e.code();
    }
    catch (...) {
        return 456;
    }
    return 789;
}

int main() {
    return run_test();
}

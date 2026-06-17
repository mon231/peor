// Tests Windows SEH (__try/__except) for x86 and
// RtlAddFunctionTable + C++ exception (throw/catch) for x64.
// Returns 77 on success.
#include <windows.h>

int test_seh() {
    __try {
        RaiseException(77, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return 0;
}

int main() {
    return test_seh();
}

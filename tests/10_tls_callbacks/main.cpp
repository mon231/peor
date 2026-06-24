// Tests that peor invokes TLS callbacks before the entry point.
// Returns 88 if the TLS callback ran (set g_result=88 on DLL_PROCESS_ATTACH).
#include <windows.h>

static volatile int g_result = 0;

static void NTAPI tls_callback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH)
        g_result = 88;
}

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_cb_ptr = tls_callback;
#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

class MCLS final
{
public:
    explicit MCLS(const int num) : _num(num)
    {}

    ~MCLS() = default;

    int get_num() const
    {
        return _num;
    }

private:
    int _num;
};

static MCLS foo()
{
    static MCLS mcls{g_result};
    return mcls;
}

int main() {
    foo();
    foo();
    foo();
    return foo().get_num();
}

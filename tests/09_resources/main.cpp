// Tests embedded-resources (.rsrc section) are preserved across shellcodification.
// Uses __ImageBase as HMODULE to read string resource 100 from the PE itself.
// Returns 42 on success, 1 if resource not found, 2 if content mismatch.
#include <windows.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;

#define PROGRAM_EXIT_CODE (42)
int main()
{
    HMODULE hMod = reinterpret_cast<HMODULE>(&__ImageBase);

    wchar_t buf[256] = {};
    int len = LoadStringW(hMod, 100, buf, 256);

    if (len <= 0)
    {
        return 1;
    }

    const wchar_t expected[] = L"PEOR_RESOURCE_TEST";
    for (int i = 0; i < len; i++)
    {
        if (buf[i] != expected[i])
        {
            return 2;
        }
    }

    return PROGRAM_EXIT_CODE;
}

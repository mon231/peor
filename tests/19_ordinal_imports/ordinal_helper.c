#include <windows.h>

int ByNameFunc(void) { return 30; }
int OrdinalOnlyFunc(void) { return 12; }

BOOL WINAPI DllMain(HINSTANCE _, DWORD __, LPVOID ___)
{
    return TRUE;
}

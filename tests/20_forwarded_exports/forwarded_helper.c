// just a module whose GetCurrentProcessId_via_forward implementation is forward import to KERNEL32 dll
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE _, DWORD __, LPVOID ___)
{
    return TRUE;
}

#include <windows.h>

int ByNameFunc(void) { return 30; }
int OrdinalOnlyFunc(void) { return 12; }

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    (void)h; (void)r; (void)p;
    return TRUE;
}

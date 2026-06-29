#include <windows.h>

/* forwarded_helper.dll contains no code for GetCurrentProcessId_via_forward —
   it is a forwarded export defined in forwarded_helper.def that redirects to
   KERNEL32.GetCurrentProcessId. DllMain is required for a valid DLL. */
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    (void)h; (void)r; (void)p;
    return TRUE;
}

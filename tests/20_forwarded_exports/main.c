#include <windows.h>

/* GetCurrentProcessId_via_forward is exported by forwarded_helper.dll as a forwarded
   export: "KERNEL32.GetCurrentProcessId". Tests that our shellcode resolver calls
   GetProcAddress which follows the forward chain to the real implementation. */
extern DWORD WINAPI GetCurrentProcessId_via_forward(void);

#define EXPECTED_RETURN 77

int main(void) {
    DWORD pid = GetCurrentProcessId_via_forward();
    return (pid != 0) ? EXPECTED_RETURN : 0;
}

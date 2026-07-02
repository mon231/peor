// Test the shellcode resolves forward imports
#include <windows.h>

#define PROGRAM_EXIT_CODE (77)
extern DWORD WINAPI GetCurrentProcessId_via_forward(void);

int main(void)
{
    DWORD pid = GetCurrentProcessId_via_forward();
    return (pid != 0) ? PROGRAM_EXIT_CODE : 0;
}

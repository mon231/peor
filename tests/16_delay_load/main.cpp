// Test shellcode resolves delay-load dependencies
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "delayimp.lib")

#include <windows.h>
#include <mmsystem.h>

int main()
{
    const DWORD start = timeGetTime();
    const DWORD end = timeGetTime();
    const DWORD duration = end - start;
    return static_cast<int>((duration % 137) + 67);
}

#pragma comment(lib, "delayimp.lib")
#pragma comment(lib, "winmm.lib")
#include <windows.h>
#include <mmsystem.h>

int main() {
    DWORD tick = timeGetTime();
    return (int)((tick % 250) + 1);  // always 1..250
}

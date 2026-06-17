// WinAPI, custom entrypoint (no CRT), Windows subsystem.
// Links user32.lib + kernel32.lib; no CRT startup code.
#include <windows.h>

int main(void) {
    MessageBoxA(NULL, "Hello from PEOR!", "PEOR Test", MB_OK);
    ExitProcess(0);
}

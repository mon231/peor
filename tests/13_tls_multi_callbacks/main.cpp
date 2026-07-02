// Tests the shellcode invokes multiple TLS-callbacks (and follows the declaration order)
#include <windows.h>
static volatile int g_counter = 0;

static void NTAPI cb1(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_counter = g_counter * 10 + 1;
}

static void NTAPI cb2(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_counter = g_counter * 10 + 2;
}

static void NTAPI cb3(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_counter = g_counter * 10 + 3;
}

static void NTAPI cb4(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_counter = g_counter * 10 + 4;
}

static void NTAPI cb5(PVOID, DWORD reason, PVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_counter = g_counter * 10 + 5;
}

#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLC", read)
#pragma section(".CRT$XLD", read)
#pragma section(".CRT$XLE", read)
#pragma section(".CRT$XLF", read)

__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK p_cb1 = cb1;
__declspec(allocate(".CRT$XLC")) PIMAGE_TLS_CALLBACK p_cb2 = cb2;
__declspec(allocate(".CRT$XLD")) PIMAGE_TLS_CALLBACK p_cb3 = cb3;
__declspec(allocate(".CRT$XLE")) PIMAGE_TLS_CALLBACK p_cb4 = cb4;
__declspec(allocate(".CRT$XLF")) PIMAGE_TLS_CALLBACK p_cb5 = cb5;

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

int main()
{
    return g_counter;
}

// Test shellcode imports from api-ms-win OS-ApiSet

#include <windows.h>
#define PROGRAM_EXIT_CODE (42)

int main(void)
{
    HANDLE heap = GetProcessHeap();
    if (!heap) { return 0; }

    void* const buf = HeapAlloc(heap, 0, sizeof(int));
    if (!buf) { return 0; }

    *(int*)buf = PROGRAM_EXIT_CODE;
    const int result = *(int*)buf;

    HeapFree(heap, 0, buf);
    return result;
}

#include <windows.h>

/* Import HeapAlloc/HeapFree/GetProcessHeap from api-ms-win-core-heap-l1-1-0.dll.
   This virtual API set DLL has no file on disk; on modern Windows, LoadLibraryA
   resolves it via the OS ApiSet schema to the real implementation in kernelbase.dll.
   The PE is built against api-ms-win-core-heap-l1-1-0.lib (see vcxproj) so the
   IMPORT DIRECTORY lists that virtual DLL name, exercising peor's resolver path. */

#define MAGIC_VALUE 42

int main(void) {
    HANDLE heap = GetProcessHeap();
    if (!heap)
        return 0;
    void *buf = HeapAlloc(heap, 0, sizeof(int));
    if (!buf)
        return 0;
    *(int *)buf = MAGIC_VALUE;
    int result = *(int *)buf;
    HeapFree(heap, 0, buf);
    return result;
}

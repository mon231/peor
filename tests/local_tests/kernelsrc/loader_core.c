/* SC-Service loader for the peor local-test VS solution: the FIXED driver.
 *
 * Built by the WDK as a normal kernel-mode driver (ntoskrnl imports come
 * from ntoskrnl.lib; no payload data is compiled in). On DriverEntry it
 * reads the peor kernel chain shellcode FROM THE FILE C:\shellcode (the
 * per-test artifact the test suite pushes before starting the service),
 * copies it into executable non-paged pool and calls it - the real ring-0
 * execution of the peor output (its SIDT-based import resolver plus the
 * payload code). The chain's NTSTATUS is written to the VM's
 * C:\Windows\Temp\peor_chain_result.txt as:
 *   PEOR_CHAIN_RESULT=0x<status>
 * DriverUnload frees the pool so `sc stop <svc>` unloads cleanly. On any
 * load failure the pool is freed BEFORE the failing status is returned
 * (DriverUnload will not run after a failed DriverEntry).
 */
#include <ntifs.h>
#include "payload_common.h"

static PVOID g_peorChainPool = NULL;

#define PEOR_POOL_TAG 'PEOR'

/* Rest policing guard: the chain entry (kernel64 prologue + resolvers +
 * chain manifest + payload image) is never this small; refuse literally
 * tiny files so a missing/garbage C:\shellcode can never be CALLED.
 */
#define PEOR_MIN_CHAIN_SIZE 0x20

static VOID PeorLoaderUnload(PDRIVER_OBJECT LoaderObject)
{
    UNREFERENCED_PARAMETER(LoaderObject);
    if (g_peorChainPool != NULL) {
        ExFreePoolWithTag(g_peorChainPool, PEOR_POOL_TAG);
        g_peorChainPool = NULL;
    }
}

static VOID PeorRecordChainStatus(NTSTATUS ChainStatus)
{
    UNICODE_STRING markerPath;
    CHAR           text[64];
    const CHAR*    prefix = "PEOR_CHAIN_RESULT=0x";
    const CHAR*    hexCharset = "0123456789ABCDEF";
    int            i, n = 0;
    const CHAR*    p;

    for (p = prefix; *p; ++p)
        text[n++] = *p;
    for (i = 7; i >= 0; --i)
        text[n++] = hexCharset[((unsigned long)ChainStatus >> (i * 4)) & 0xF];
    text[n++] = '\r';
    text[n++] = '\n';

    PeorInitPath(&markerPath, PEOR_MARK_ROOT L"peor_chain_result.txt");
    PeorWriteMarkerBuffer(&markerPath, text, (ULONG)n);
}

static NTSTATUS PeorReadShellcodeFile(PVOID Buffer, ULONG* ByteCount)
{
    UNICODE_STRING           path;
    OBJECT_ATTRIBUTES        oa;
    IO_STATUS_BLOCK          ios;
    FILE_STANDARD_INFORMATION std = {0};
    HANDLE                   file = NULL;
    NTSTATUS                 st;

    PeorInitPath(&path, L"\\??\\C:\\shellcode");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE |
                               OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&file,
                      FILE_GENERIC_READ,
                      &oa, &ios, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                      FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    DbgPrint("PEORLOADER: open shellcode=0x%lX\n", st);
    if (!NT_SUCCESS(st))
        return st;

    st = ZwQueryInformationFile(file, &ios, &std,
                               sizeof(std), FileStandardInformation);
    if (!NT_SUCCESS(st))
        goto out;
    DbgPrint("PEORLOADER: shellcode size=0x%llX\n",
             (unsigned long long)std.EndOfFile.QuadPart);
    if (std.EndOfFile.QuadPart <= PEOR_MIN_CHAIN_SIZE ||
        std.EndOfFile.QuadPart > 0x00100000) {
        st = STATUS_INVALID_BUFFER_SIZE;
        goto out;
    }
    *ByteCount = (ULONG)std.EndOfFile.QuadPart;

    st = ZwReadFile(file, NULL, NULL, NULL, &ios, Buffer, *ByteCount,
                    NULL, NULL);
    DbgPrint("PEORLOADER: read=0x%lX got=0x%llX\n",
             st, (unsigned long long)ios.Information);
    if (NT_SUCCESS(st) && ios.Information != *ByteCount)
        st = STATUS_IO_TIMEOUT;

out:
    ZwClose(file);
    return st;
}

EXTERN_C NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT LoaderObject,
                                    PUNICODE_STRING RegistryPath)
{
    typedef NTSTATUS (NTAPI *PEOR_CHAIN_ENTRY_FN)(void);
    ULONG   chainBytes = 0;
    NTSTATUS status;
    LARGE_INTEGER stub;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("PEORLOADER: entry\n");
    LoaderObject->DriverUnload = PeorLoaderUnload;

    /* Upper bound: 1 MiB chain (the biggest payload chain emitted so far
     * is ~0x7100 bytes; 1 MiB is a generous, nameable limit). */
    stub.QuadPart = 0x00100000;
    g_peorChainPool = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                      (SIZE_T)stub.QuadPart,
                                      PEOR_POOL_TAG);
    DbgPrint("PEORLOADER: pool=%p cap=0x%llX\n",
             g_peorChainPool, (unsigned long long)stub.QuadPart);
    if (g_peorChainPool == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        PeorRecordChainStatus(status);
        return status;
    }

    status = PeorReadShellcodeFile(g_peorChainPool, &chainBytes);
    if (!NT_SUCCESS(status)) {
        PeorRecordChainStatus(status);
        ExFreePoolWithTag(g_peorChainPool, PEOR_POOL_TAG);
        g_peorChainPool = NULL;
        return status;
    }

    status = ((PEOR_CHAIN_ENTRY_FN)g_peorChainPool)();
    DbgPrint("PEORLOADER: chain bytes=0x%lX status=0x%lX back\n",
             chainBytes, status);
    PeorRecordChainStatus(status);

    return status;
}

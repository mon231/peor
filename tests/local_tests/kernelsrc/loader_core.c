/* SC-Service loader embedding a real peor kernel64 chain blob.
 *
 * Built by the WDK as a normal kernel-mode driver (ntoskrnl imports come
 * from ntoskrnl.lib; the chain bytes, not the imports, come from the
 * generated chain_blob.inc produced by _kernel_chain_build from a
 * `python -m peor` output).
 *
 * DriverEntry:
 *  1. allocates executable non-paged pool (NonPagedPool, value 0),
 *  2. copies the embedded peor chain blob into it,
 *  3. calls the blob - the real ring-0 execution of the peor output
 *     (its SIDT-based import resolver plus the payload code),
 *  4. writes "PEOR_CHAIN_RESULT=0x<status>" to the VM's
 *     C:\Windows\Temp\peor_chain_result.txt,
 *  5. registers DriverUnload so `sc stop <svc>` frees the pool.
 */
#include <ntifs.h>
#include "payload_common.h"
#include "chain_blob.inc"

static PVOID g_peorChainPool = NULL;

#define PEOR_POOL_TAG 'PEOR'

static VOID PeorLoaderUnload(PDRIVER_OBJECT LoaderObject)
{
    UNREFERENCED_PARAMETER(LoaderObject);
    if (g_peorChainPool != NULL) {
        ExFreePoolWithTag(g_peorChainPool, PEOR_POOL_TAG);
        g_peorChainPool = NULL;
    }
}

EXTERN_C NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT LoaderObject,
                                    PUNICODE_STRING RegistryPath)
{
    typedef NTSTATUS (NTAPI *PEOR_CHAIN_ENTRY_FN)(void);
    UNICODE_STRING markerPath;
    CHAR           text[64];
    const CHAR*    prefix = "PEOR_CHAIN_RESULT=0x";
    const CHAR*    hexCharset = "0123456789ABCDEF";
    NTSTATUS       status;
    int            i, n = 0;
    const CHAR*    p;

    UNREFERENCED_PARAMETER(RegistryPath);
    LoaderObject->DriverUnload = PeorLoaderUnload;

    g_peorChainPool = ExAllocatePoolWithTag(NonPagedPool,
                                            sizeof(peorChainBlob),
                                            PEOR_POOL_TAG);
    if (g_peorChainPool == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(g_peorChainPool,
                  (const VOID*)peorChainBlob,
                  sizeof(peorChainBlob));

    status = ((PEOR_CHAIN_ENTRY_FN)g_peorChainPool)();

    for (p = prefix; *p; ++p)
        text[n++] = *p;
    for (i = 7; i >= 0; --i)
        text[n++] = hexCharset[((unsigned long)status >> (i * 4)) & 0xF];
    text[n++] = '\r';
    text[n++] = '\n';

    PeorInitPath(&markerPath, PEOR_MARK_ROOT L"peor_chain_result.txt");
    PeorWriteMarkerBuffer(&markerPath, text, (ULONG)n);

    return status;
}

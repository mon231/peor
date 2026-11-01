/* Common helpers for peor local-test payloads (kernel mode, no CRT).
 *
 * Each payload writes its result marker on the VM filesystem so the test
 * can verify the real ring-0 chain executed:
 *   calc  -> C:\Windows\Temp\peor_calc_result.txt   "PEOR_CALC=<sum>"
 *   spawn -> C:\Windows\Temp\peor_spawn_status.txt  per-step NTSTATUSes
 * The spawn payload's child process writes its own marker on its own, the
 * hard proof that a real user-mode process ran (see child_entry.c).
 */
#ifndef PEOR_PAYLOAD_COMMON_H
#define PEOR_PAYLOAD_COMMON_H

#include <ntifs.h>

#define PEOR_MARK_ROOT L"\\??\\C:\\Windows\\Temp\\"

/* Shared helper: supersede a text marker file; NULL on failure. HANDLE via
 * ZwCreateFile, plain UTF-8-ish bytes through ZwWriteFile (ZwClose after). */
static VOID PeorWriteMarkerBuffer(PUNICODE_STRING Path, const CHAR* Data,
                                  ULONG Length)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   ios;
    LARGE_INTEGER     alloc;
    HANDLE            file = NULL;
    NTSTATUS          st;

    alloc.QuadPart = 0;
    InitializeObjectAttributes(&oa, Path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    st = ZwCreateFile(&file,
                      FILE_WRITE_DATA | SYNCHRONIZE,
                      &oa, &ios, &alloc,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OVERWRITE_IF,
                      FILE_SYNCHRONOUS_IO_NONALERT,
                      NULL, 0);
    if (!NT_SUCCESS(st))
        return;
    ZwWriteFile(file, NULL, NULL, NULL, &ios,
                (PVOID)Data, Length, NULL, NULL);
    ZwClose(file);
}

/* Build a UNICODE_STRING from a literal (documented Rtl* import). */
static VOID PeorInitPath(PUNICODE_STRING Path, PCWSTR Lit)
{
    RtlInitUnicodeString(Path, Lit);
}

#endif /* PEOR_PAYLOAD_COMMON_H */

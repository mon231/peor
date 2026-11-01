/* Real user-mode process spawn payload for the peor local-test suite.
 *
 * Built by the WDK (NATIVE .sys), converted to a peor kernel64 chain blob
 * with `python -m peor`, and called in real ring-0 by the SCM loader.
 * From DriverEntry we create a REAL user-mode child process from scratch:
 * all the undocumented kernel exports involved are resolved at run time
 * via the documented MmGetSystemRoutineAddress, so nothing depends on
 * which symbols happen to be exported on the target kernel build.
 *
 * Steps, all visible as NTSTATUS lines in the status marker:
 *   1. ZwCreateSection over an image of
 *      \??\C:\Windows\System32\cmd.exe (real MS binary, always present).
 *   2. ZwCreateProcessEx (9-arg Win8+ form, flags= 0, no inherit).
 *   3. ObReferenceObjectByHandle -> child PEPROCESS; KeStackAttachProcess.
 *   4. ZwAllocateVirtualMemory in the child: 0x4000 params + strings +
 *      a simple environment; fill RTL_USER_PROCESS_PARAMETERS (x64
 *      offsets), PEB->ImageBaseAddress + EntryRva via RtlImageNtHeader,
 *      then PEB->ProcessParameters = paramsBase.
 *   5. KeUnstackDetachProcess, then RtlCreateUserThread (suspended) with
 *      StartAddress = imageBase + entryRVA.
 *   6. ZwResumeThread - cmd.exe runs `dir C:\` redirected into
 *      C:\Windows\Temp\peor_spawn_cmds.txt; that file (written by the
 *      CHILD PROCESS ITSELF) is what the test asserts.
 *   7. Wait (45 s), then Marque file
 *      C:\Windows\Temp\peor_spawn_status.txt with each step's NTSTATUS
 *      and a summary; terminate if the child is still running.
 *
 * x64-only RTL_USER_PROCESS_PARAMETERS offsets. SYSTEM context assumed
 * (SCM loads this from the System process) so NtCurrentProcess() is a
 * valid parent for the child.
 */
#include "payload_common.h"

#define PEOR_IMAGE_PATH_TO_SPAWN   L"\\??\\C:\\Windows\\System32\\cmd.exe"
#define PEOR_IMAGE_PATHNAME        L"C:\\Windows\\System32\\cmd.exe"
#define PEOR_IMAGE_COMMAND_LINE    L"cmd.exe /C dir C:\\ > C:\\Windows\\Temp\\peor_spawn_cmds.txt 2>&1"

#define PEOR_MEM_COMMIT       0x1000
#define PEOR_MEM_RESERVE      0x2000
#define PEOR_PAGE_RW          0x4
#define PEOR_PAGE_READONLY    0x2
#define PEOR_SEC_IMAGE        0x1000000
#define PEOR_SECTION_QUERY    0x1
#define PEOR_SECTION_MAP_READ 0x4
#define PEOR_SECTION_MAP_WRITE   0x2
#define PEOR_SECTION_MAP_EXECUTE 0x8
#define PEOR_GENERIC_READ     0x80000000
#define PEOR_PROCESS_ALL_ACCESS 0x1FFFFF

#define PEOR_UPP_NORMALIZED   0x1
#define PEOR_PEB_IMAGEBASE_OFF  0x10
#define PEOR_PEB_PARAMS_OFF   0x20

/* Undocumented kernel exports; resolved at run time. */
typedef NTSTATUS (NTAPI *FN_ZWCREATESECTION)
    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *FN_ZWCREATEPROCESSEX)
    (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
typedef NTSTATUS (NTAPI *FN_ZWALLOCVM)
    (HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *FN_ZWRESUMETHREAD)
    (HANDLE, PULONG);
typedef NTSTATUS (NTAPI *FN_ZWWAITOBJ)
    (HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *FN_ZWTERMPROC)
    (HANDLE, NTSTATUS);
typedef NTSTATUS (NTAPI *FN_RTLCREUSERTHREAD)
    (HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, ULONG, ULONG,
     PVOID, PVOID, PHANDLE, PCLIENT_ID);
typedef PVOID (NTAPI *FN_PSGETPROCESSPEB)(PEPROCESS);

/* Documented RTL_USER_PROCESS_PARAMETERS layout (x64). */
#pragma pack(push, 8)
typedef struct _PEOR_UPP {
    ULONG          MaximumLength;         /* 0x00 */
    ULONG          Length;                /* 0x04 */
    ULONG          Flags;                 /* 0x08 */
    ULONG          DebugFlags;            /* 0x0C */
    PVOID          ConsoleHandle;         /* 0x10 */
    ULONG          ConsoleFlags;          /* 0x18 */
    ULONG          Pad0;                  /* 0x1C */
    PVOID          StandardInput;         /* 0x20 */
    PVOID          StandardOutput;        /* 0x28 */
    PVOID          StandardError;         /* 0x30 */
    UNICODE_STRING CurrentDirectoryDosPath;  /* 0x38 */
    HANDLE         CurrentDirectoryHandle;   /* 0x48 */
    UNICODE_STRING DllPath;               /* 0x50 */
    UNICODE_STRING ImagePathName;         /* 0x60 */
    UNICODE_STRING CommandLine;           /* 0x70 */
    PVOID          Environment;           /* 0x80 */
} PEOR_UPP;
#pragma pack(pop)

typedef char peor_upp_layout_check[(sizeof(PEOR_UPP) == 0x88) ? 1 : -1];

/* String-composition slots inside the allocated params page. */
#define PEOR_STR_IMAGE      0x200
#define PEOR_STR_CMDLINE    0x300
#define PEOR_STR_ENV        0x400
#define PEOR_STR_ENV_MAX    0x800
#define PEOR_PARAMS_ALLOCSZ 0x2000

static VOID PeorAppendStrA(CHAR* Dst, ULONG* At, ULONG Max, const CHAR* S)
{
    while (*S && *At < Max) Dst[(*At)++] = *S++;
}

static VOID PeorAppendHexA(CHAR* Dst, ULONG* At, ULONG Max, ULONG Value)
{
    static const CHAR hexc[] = "0123456789ABCDEF";
    int i;
    for (i = 7; i >= 0 && *At < Max; --i)
        Dst[(*At)++] = hexc[(Value >> (i * 4)) & 0xF];
}

static VOID PeorAppendNtA(CHAR* Dst, ULONG* At, ULONG Max, NTSTATUS S)
{
    PeorAppendStrA(Dst, At, Max, "0x");
    PeorAppendHexA(Dst, At, Max, (ULONG)S);
}

static PVOID PeorResolveRoutine(PCWSTR Name)
{
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, Name);
    return MmGetSystemRoutineAddress(&us);
}

static ULONG PeorWriteUtf16(PVOID ParamsBase, ULONG ByteOffset, PCWSTR Text)
{
    WCHAR* dst = (WCHAR*)((PUCHAR)ParamsBase + ByteOffset);
    ULONG  count = 0;
    while (*Text) dst[count++] = *Text++;
    dst[count++] = 0;
    return count * sizeof(WCHAR);
}

static ULONG PeorComposeEnvBlock(PVOID ParamsBase)
{
    static const WCHAR* entries[] = {
        L"COMSPEC=C:\\Windows\\System32\\cmd.exe",
        L"PATH=C:\\Windows\\System32",
        L"SystemRoot=C:\\Windows",
        NULL
    };
    WCHAR* env = (WCHAR*)((PUCHAR)ParamsBase + PEOR_STR_ENV);
    ULONG  n = 0, i;
    for (i = 0; entries[i]; ++i) {
        const WCHAR* e = entries[i];
        while (*e) env[n++] = *e++;
        env[n++] = 0;
    }
    env[n++] = 0;
    return n * sizeof(WCHAR);
}

static VOID PeorFillProcessParameters(PVOID ParamsBase,
                                      ULONG ImagePathBytes,
                                      ULONG CommandLineBytes,
                                      ULONG EnvBytes)
{
    PEOR_UPP* upp = (PEOR_UPP*)ParamsBase;

    upp->MaximumLength         = PEOR_PARAMS_ALLOCSZ;     /* whole page */
    upp->Length                = 0x88;                    /* struct size */
    upp->Flags                 = PEOR_UPP_NORMALIZED;
    upp->DebugFlags            = 0;
    upp->ConsoleHandle         = NULL;
    upp->ConsoleFlags          = 0;
    upp->StandardInput         = NULL;
    upp->StandardOutput        = NULL;
    upp->StandardError         = NULL;

    upp->CurrentDirectoryDosPath.Length        = 0;
    upp->CurrentDirectoryDosPath.MaximumLength = 0;
    upp->CurrentDirectoryDosPath.Buffer        = NULL;
    upp->CurrentDirectoryHandle                = NULL;

    upp->DllPath.Length        = 0;
    upp->DllPath.MaximumLength = 0;
    upp->DllPath.Buffer        = NULL;

    upp->ImagePathName.Length        = (USHORT)ImagePathBytes;
    upp->ImagePathName.MaximumLength = (USHORT)(ImagePathBytes + sizeof(WCHAR));
    upp->ImagePathName.Buffer        = (PWSTR)((PUCHAR)ParamsBase + PEOR_STR_IMAGE);

    upp->CommandLine.Length          = (USHORT)CommandLineBytes;
    upp->CommandLine.MaximumLength   = (USHORT)(CommandLineBytes + sizeof(WCHAR));
    upp->CommandLine.Buffer          = (PWSTR)((PUCHAR)ParamsBase + PEOR_STR_CMDLINE);

    upp->Environment = (PVOID)((PUCHAR)ParamsBase + PEOR_STR_ENV);
    (void)EnvBytes;
}

EXTERN_C NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT Loader, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(Loader);
    UNREFERENCED_PARAMETER(RegPath);

    FN_ZWCREATESECTION      ZWCREATESECTION_f;
    FN_ZWCREATEPROCESSEX    ZWCREATEPROCESSEX_f;
    FN_ZWALLOCVM            ZWALLOCVM_f;
    FN_ZWRESUMETHREAD       ZWRESUMETHREAD_f;
    FN_ZWWAITOBJ            ZWWAITOBJ_f;
    FN_ZWTERMPROC           ZWTERMPROC_f;
    FN_RTLCREUSERTHREAD     RTLCREATEUSERTHREAD_f;
    FN_PSGETPROCESSPEB      PSGETPROCESSPEB_f;

    UNICODE_STRING  childPath;
    UNICODE_STRING  statusPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK ios;
    LARGE_INTEGER   allocSize;
    LARGE_INTEGER   timeout;
    NTSTATUS        stSection, stProcess, st = STATUS_SUCCESS;
    HANDLE          file    = NULL;
    HANDLE          section = NULL;
    HANDLE          process = NULL;
    HANDLE          thread  = NULL;
    PVOID           eproc   = NULL;
    PVOID           childPeb = NULL;
    PVOID           paramsBase = NULL;
    PVOID           imageBase  = NULL;
    ULONG           entryRva   = 0;
    ULONG           imageBytes = 0;
    ULONG           cmdlineBytes = 0;
    ULONG           envBytes = 0;
    ULONG           at = 0;
    ULONG           prevSuspend = 0;
    CHAR            text[1024];
    CLIENT_ID       clientId;
    KAPC_STATE      apcState;

    /* ---- resolve routine pointers (name-based on the VM's kernel) ---- */
    ZWCREATESECTION_f      = (FN_ZWCREATESECTION)PeorResolveRoutine(L"ZwCreateSection");
    ZWCREATEPROCESSEX_f    = (FN_ZWCREATEPROCESSEX)PeorResolveRoutine(L"ZwCreateProcessEx");
    ZWALLOCVM_f            = (FN_ZWALLOCVM)PeorResolveRoutine(L"ZwAllocateVirtualMemory");
    ZWRESUMETHREAD_f       = (FN_ZWRESUMETHREAD)PeorResolveRoutine(L"ZwResumeThread");
    ZWWAITOBJ_f            = (FN_ZWWAITOBJ)PeorResolveRoutine(L"ZwWaitForSingleObject");
    ZWTERMPROC_f           = (FN_ZWTERMPROC)PeorResolveRoutine(L"ZwTerminateProcess");
    RTLCREATEUSERTHREAD_f  = (FN_RTLCREUSERTHREAD)PeorResolveRoutine(L"RtlCreateUserThread");
    PSGETPROCESSPEB_f      = (FN_PSGETPROCESSPEB)PeorResolveRoutine(L"PsGetProcessPeb");

    PeorAppendStrA(text, &at, sizeof(text), "PEOR_SPAWN=trying\r\n");
    PeorAppendStrA(text, &at, sizeof(text), "SECTION=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (ZWCREATESECTION_f == NULL) ? STATUS_NOT_FOUND : 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nCREATEPROCESS=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (ZWCREATEPROCESSEX_f == NULL) ? STATUS_NOT_FOUND : 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nALLOCVM=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (ZWALLOCVM_f == NULL) ? STATUS_NOT_FOUND : 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nRESUME=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (ZWRESUMETHREAD_f == NULL) ? STATUS_NOT_FOUND : 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nUSERTHREAD=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (RTLCREATEUSERTHREAD_f == NULL) ? STATUS_NOT_FOUND : 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nGETPROCESSPEB=");
    PeorAppendNtA(text, &at, sizeof(text),
                  (PSGETPROCESSPEB_f == NULL) ? STATUS_NOT_FOUND : 0);

    if (ZWCREATESECTION_f == NULL || ZWCREATEPROCESSEX_f == NULL ||
        ZWALLOCVM_f == NULL || ZWRESUMETHREAD_f == NULL ||
        RTLCREATEUSERTHREAD_f == NULL || PSGETPROCESSPEB_f == NULL ||
        ZWWAITOBJ_f == NULL || ZWTERMPROC_f == NULL) {
        PeorAppendStrA(text, &at, sizeof(text), "\r\nPEOR_SPAWN=MISSING_ROUTINE\r\n");
        goto dump;      /* one unrecoverable missing routine */
    }

    /* ---- 1. open cmd.exe ---- */
    RtlInitUnicodeString(&childPath, PEOR_IMAGE_PATH_TO_SPAWN);
    InitializeObjectAttributes(&oa, &childPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    allocSize.QuadPart = 0;
    st = ZwCreateFile(&file,
                      SYNCHRONIZE | PEOR_GENERIC_READ,
                      &oa, &ios, &allocSize,
                      FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ | FILE_SHARE_DELETE,
                      FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT,
                      NULL, 0);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nOPENFILE=");
    PeorAppendNtA(text, &at, sizeof(text), st);
    if (!NT_SUCCESS(st))
        goto dump;

    /* ---- 2. build a section over the image ---- */
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    stSection = ZWCREATESECTION_f(&section,
                                  PEOR_SECTION_QUERY | PEOR_SECTION_MAP_READ |
                                  PEOR_SECTION_MAP_WRITE | PEOR_SECTION_MAP_EXECUTE,
                                  &oa, NULL, PEOR_PAGE_READONLY,
                                  PEOR_SEC_IMAGE, file);
    ZwClose(file);
    file = NULL;
    PeorAppendStrA(text, &at, sizeof(text), "\r\nSECTION=");
    PeorAppendNtA(text, &at, sizeof(text), stSection);
    if (!NT_SUCCESS(stSection)) {
        st = stSection;
        goto dump;
    }

    /* ---- 3. create the process over that image ---- */
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    stProcess = ZWCREATEPROCESSEX_f(&process,
                                    PEOR_PROCESS_ALL_ACCESS,
                                    &oa, (HANDLE)NtCurrentProcess(),
                                    0 /* no inherit flags */,
                                    section, NULL, NULL, 0);
    ZwClose(section);
    section = NULL;
    PeorAppendStrA(text, &at, sizeof(text), "\r\nCREATEPROCESS=");
    PeorAppendNtA(text, &at, sizeof(text), stProcess);
    if (!NT_SUCCESS(stProcess)) {
        st = stProcess;
        goto dump;
    }

    /* ---- 4. reference + attach + fill user-mode params ---- */
    st = ObReferenceObjectByHandle(process, PEOR_PROCESS_ALL_ACCESS,
                                   (POBJECT_TYPE)NULL, KernelMode,
                                   &eproc, NULL);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nREFPROCESS=");
    PeorAppendNtA(text, &at, sizeof(text), st);
    if (!NT_SUCCESS(st))
        goto dump;

    KeStackAttachProcess((PRKPROCESS)eproc, &apcState);

    {
        SIZE_T  region = PEOR_PARAMS_ALLOCSZ;
        paramsBase = NULL;
        st = ZWALLOCVM_f(process, &paramsBase, 0, &region,
                         PEOR_MEM_COMMIT | PEOR_MEM_RESERVE, PEOR_PAGE_RW);
        PeorAppendStrA(text, &at, sizeof(text), "\r\nALLOCVM=");
        PeorAppendNtA(text, &at, sizeof(text), st);
        if (!NT_SUCCESS(st)) {
            KeUnstackDetachProcess(&apcState);
            goto dump;
        }
        RtlZeroMemory(paramsBase, PEOR_PARAMS_ALLOCSZ);
        imageBytes  = PeorWriteUtf16(paramsBase, PEOR_STR_IMAGE,
                                     PEOR_IMAGE_PATHNAME);
        cmdlineBytes = PeorWriteUtf16(paramsBase, PEOR_STR_CMDLINE,
                                      PEOR_IMAGE_COMMAND_LINE);
        envBytes = PeorComposeEnvBlock(paramsBase);
        PeorFillProcessParameters(paramsBase, imageBytes, cmdlineBytes, envBytes);
    }

    childPeb = (PPEB)PSGETPROCESSPEB_f((PEPROCESS)eproc);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nGETPROCESSPEB=");
    PeorAppendNtA(text, &at, sizeof(text),
                  childPeb ? 0 : STATUS_INVALID_PARAMETER);
    if (childPeb == NULL) {
        KeUnstackDetachProcess(&apcState);
        goto dump;
    }

    {
        LONG        e_lfanew;
        imageBase = *(PVOID**)((PUCHAR)childPeb + PEOR_PEB_IMAGEBASE_OFF);
        /* Read the mapped image's PE header directly (attached): DOS
         * e_lfanew at +0x3C, NT header OptionalHeader.AddressOfEntry
         * Point (64-bit) at NT + 0x28. */
        e_lfanew = *(LONG*)((PUCHAR)imageBase + 0x3C);
        entryRva = *(ULONG*)((PUCHAR)imageBase + e_lfanew + 0x28);
        *(PVOID**)((PUCHAR)childPeb + PEOR_PEB_PARAMS_OFF) = paramsBase;
        PeorAppendStrA(text, &at, sizeof(text), "\r\nIMAGEBASE=0x");
        PeorAppendHexA(text, &at, sizeof(text),
                       (ULONG)(((ULONG_PTR)imageBase) & 0xFFFFFFFF));
        PeorAppendStrA(text, &at, sizeof(text), "+0x");
        PeorAppendHexA(text, &at, sizeof(text),
                       (ULONG)(((ULONG_PTR)imageBase) >> 32));
        PeorAppendStrA(text, &at, sizeof(text), " ENTRYRVA=");
        PeorAppendHexA(text, &at, sizeof(text), entryRva);
    }
    KeUnstackDetachProcess(&apcState);

    /* ---- 5. create the suspended user thread that runs cmd.exe ---- */
    clientId.UniqueProcess = NULL;
    clientId.UniqueThread  = NULL;
    st = RTLCREATEUSERTHREAD_f(process, NULL, TRUE /* suspended */,
                               0, 0x00100000 /* reserve 1 MB */,
                               0x00040000 /* commit 256 KB */,
                               (PVOID)(((ULONG_PTR)imageBase) + entryRva),
                               NULL, &thread, &clientId);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nUSERTHREAD=");
    PeorAppendNtA(text, &at, sizeof(text), st);
    if (!NT_SUCCESS(st))
        goto dump;

    /* ---- 6. resume ---- */
    st = ZWRESUMETHREAD_f(thread, &prevSuspend);
    PeorAppendStrA(text, &at, sizeof(text), "\r\nRESUME=");
    PeorAppendNtA(text, &at, sizeof(text), st);
    if (!NT_SUCCESS(st))
        goto dump;

    /* ---- 7. wait for the child process to terminate ---- */
    timeout.QuadPart = -(45LL * 10000000LL);   /* 45 s into the future */
    st = ZWWAITOBJ_f(process, FALSE, &timeout);
    if (st == STATUS_TIMEOUT && ZWTERMPROC_f != NULL) {
        ZWTERMPROC_f(process, STATUS_TIMEOUT);
        st = STATUS_TIMEOUT;
    }
    PeorAppendStrA(text, &at, sizeof(text), "\r\nWAIT=");
    PeorAppendNtA(text, &at, sizeof(text), st);
    PeorAppendStrA(text, &at, sizeof(text),
                   "\r\nPEOR_SPAWN=process-was-real\r\n");
    st = STATUS_SUCCESS;

dump:
    if (thread) ZwClose(thread);
    if (process) ZwClose(process);
    if (file) ZwClose(file);
    if (section) ZwClose(section);
    if (eproc) ObDereferenceObject(eproc);
    PeorInitPath(&statusPath, PEOR_MARK_ROOT L"peor_spawn_status.txt");
    PeorWriteMarkerBuffer(&statusPath, text, at);
    return st;
}

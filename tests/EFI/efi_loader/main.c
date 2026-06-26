/*
 * EFI loader - runs an embedded shellcode buffer, prints result, then shuts down.
 * The shellcode bytes are injected at compile time via shellcode_data.h.
 * Supports both x64 (PE32+) and IA-32 (PE32) EFI builds via #ifdef _WIN64.
 *
 * UEFI pre-boot memory is executable by default (no NX enforcement in OVMF),
 * so calling a static array directly works without AllocatePool.
 *
 * Success detection: on EFI_SUCCESS the loader calls ResetSystem(EfiResetShutdown),
 * which causes QEMU to exit with code 0.  On failure the loader loops forever,
 * causing the test to exceed its QEMU timeout.
 *
 * Compile (after generating shellcode_data.h):
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -I. -Wl,-e,efi_loader_main -Wl,--subsystem,10 \
 *     -o efi_loader.efi main.c
 *   i686-w64-mingw32-gcc ... same flags ... -o efi_loader_ia32.efi main.c
 */

#include <stddef.h>
#include "shellcode_data.h"   /* defines: static const unsigned char SHELLCODE_BYTES[]; */

typedef unsigned char  UINT8;
typedef unsigned short UINT16;

#ifdef _WIN64
typedef unsigned long long UINTN;

/* Byte offsets into EFI_SYSTEM_TABLE (UEFI spec, x64 / 64-bit pointers). */
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#define EFI_SYSTEM_TABLE_RUNTIME_SERVICES_OFFSET 0x58
/* EFI_RUNTIME_SERVICES.ResetSystem — 11th entry, each pointer is 8 bytes.
   Header is 24 bytes; entries 0-9 (GetTime..GetNextHighMonotonicCount) take 80 bytes. */
#define EFI_RUNTIME_SERVICES_RESET_SYSTEM_OFFSET 0x68
/* EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString — 2nd member, 8-byte pointer. */
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#else
typedef unsigned int UINTN;

/* Byte offsets into EFI_SYSTEM_TABLE (UEFI spec, IA-32 / 32-bit pointers). */
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#define EFI_SYSTEM_TABLE_RUNTIME_SERVICES_OFFSET 0x38
/* EFI_RUNTIME_SERVICES.ResetSystem — 11th entry, each pointer is 4 bytes.
   Header is 24 bytes; entries 0-9 take 40 bytes. */
#define EFI_RUNTIME_SERVICES_RESET_SYSTEM_OFFSET 0x40
/* EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString — 2nd member, 4-byte pointer. */
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#endif

typedef UINTN EFI_STATUS;

#define EFI_SUCCESS      ((EFI_STATUS)0)
#define EFI_RESET_SHUTDOWN 2

static const UINT16 OK_MSG[]   = {'P','E','O','R','_','E','F','I','_','O','K','\r','\n',0};
static const UINT16 FAIL_MSG[] = {'P','E','O','R','_','E','F','I','_','F','A','I','L','\r','\n',0};

EFI_STATUS efi_loader_main(void *image_handle, void *system_table) {
    (void)image_handle;

    /* The EFI shellcode is self-contained: it scans memory for EFI_SYSTEM_TABLE_SIGNATURE
       by itself.  No parameters are passed from the loader. */
    EFI_STATUS result = ((EFI_STATUS (*)(void))SHELLCODE_BYTES)();

    /* Print result via ConOut->OutputString. */
    void **conout_slot = (void **)((UINT8 *)system_table
                                   + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    void *conout = *conout_slot;

    typedef EFI_STATUS (*OUTPUT_FN)(void *proto, const UINT16 *str);
    OUTPUT_FN output_string =
        *(OUTPUT_FN *)((UINT8 *)conout + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);

    if (result == EFI_SUCCESS) {
        output_string(conout, OK_MSG);
    } else {
        output_string(conout, FAIL_MSG);
    }

    /* Shut down the machine on success so QEMU exits 0. */
    if (result == EFI_SUCCESS) {
        void **rt_slot = (void **)((UINT8 *)system_table
                                   + EFI_SYSTEM_TABLE_RUNTIME_SERVICES_OFFSET);
        void *rt = *rt_slot;

        typedef void (*RESET_FN)(int reset_type, EFI_STATUS status,
                                 UINTN data_size, void *data);
        RESET_FN reset_system =
            *(RESET_FN *)((UINT8 *)rt + EFI_RUNTIME_SERVICES_RESET_SYSTEM_OFFSET);

        reset_system(EFI_RESET_SHUTDOWN, EFI_SUCCESS, 0, NULL);
    }

    /* Failure path: loop forever (QEMU will time out, test fails). */
    while (1) {}
    return result;
}

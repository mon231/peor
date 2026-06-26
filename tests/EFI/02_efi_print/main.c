/*
 * EFI print test - prints "PEOR_EFI_HELLO\r\n" via ConOut->OutputString.
 * Requires a real EFI_SYSTEM_TABLE pointer from the entrypoint resolver.
 *
 * Supports x64 (PE32+, amd64) and x86 (PE32, IA-32).
 * EFI_SYSTEM_TABLE layout differs per arch: ConOut at 0x40 (x64) or 0x2C (x86).
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application -o 02_efi_print.efi main.c
 */

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
/* x64 EFI_SYSTEM_TABLE layout (64-bit pointers, UEFI spec 2.x) */
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#else
typedef unsigned int EFI_STATUS;
/* x86 EFI_SYSTEM_TABLE layout (32-bit pointers) */
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#endif

typedef unsigned short CHAR16;

#define EFI_SUCCESS                              ((EFI_STATUS)0)
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08

static const CHAR16 MSG[] = {
    'P','E','O','R','_','E','F','I','_','H','E','L','L','O','\r','\n', 0
};

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);

    (void)image_handle;
    void *conout = *(void **)((unsigned char *)system_table
                              + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN output_string = *(OUTPUT_FN *)((unsigned char *)conout
                              + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);
    output_string(conout, MSG);
    return EFI_SUCCESS;
}

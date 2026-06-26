/*
 * EFI hello test - returns EFI_SUCCESS immediately.
 * Supports both x86 (PE32, IA-32) and x64 (PE32+, amd64).
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application -o efi_hello.efi main.c
 *
 * Compile (x86):
 *   i686-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application -o efi_hello_x86.efi main.c
 */

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#else
typedef unsigned int EFI_STATUS;
#endif

#define EFI_SUCCESS ((EFI_STATUS)0)

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    (void)image_handle;
    (void)system_table;
    return EFI_SUCCESS;
}

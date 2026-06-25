/*
 * Minimal EFI application - returns EFI_SUCCESS immediately.
 * Used with peor to test EFI shellcode generation.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application \
 *     -o 01_efi_hello.efi main.c
 */

typedef unsigned long long EFI_STATUS;

#define EFI_SUCCESS ((EFI_STATUS)0)

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    (void)image_handle;
    (void)system_table;
    return EFI_SUCCESS;
}

/*
 * Minimal x86 EFI application - returns EFI_SUCCESS immediately.
 * Used with peor to test EFI shellcode generation for PE32 (IA-32).
 *
 * Compile:
 *   i686-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application \
 *     -o 01_efi_hello_x86.efi main.c
 */

typedef unsigned int EFI_STATUS;

#define EFI_SUCCESS ((EFI_STATUS)0)

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    (void)image_handle;
    (void)system_table;
    return EFI_SUCCESS;
}

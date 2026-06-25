/*
 * EFI simple-calc test - computes sum(0..99)=4950, prints "PEOR_4950\r\n".
 * Requires a real EFI_SYSTEM_TABLE pointer (passed by the updated efi_loader).
 *
 * Returns EFI_SUCCESS (0) on correct result so the efi_loader shuts down QEMU.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application \
 *     -o 03_efi_simple_calc.efi main.c
 */

typedef unsigned long long EFI_STATUS;
typedef unsigned short     CHAR16;

#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_LOAD_ERROR ((EFI_STATUS)1)
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08

static const CHAR16 MSG_OK[]   = {
    'P','E','O','R','_','4','9','5','0','\r','\n', 0
};
static const CHAR16 MSG_FAIL[] = {
    'P','E','O','R','_','C','A','L','C','_','F','A','I','L','\r','\n', 0
};

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);

    (void)image_handle;
    void *conout = *(void **)((unsigned char *)system_table
                              + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN output_string = *(OUTPUT_FN *)((unsigned char *)conout
                              + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);

    int sum = 0;
    for (int i = 0; i < 100; i++) sum += i;

    if (sum == 4950) {
        output_string(conout, MSG_OK);
        return EFI_SUCCESS;
    }
    output_string(conout, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

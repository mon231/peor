/*
 * EFI simple-calc test - computes sum(0..99)=4950, prints "PEOR_4950\r\n".
 * Requires a real EFI_SYSTEM_TABLE pointer from the entrypoint resolver.
 *
 * Returns EFI_SUCCESS on correct result so the loader shuts down QEMU.
 *
 * Supports x64 (PE32+) and x86 (PE32).
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application -o 03_efi_simple_calc.efi main.c
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

#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_LOAD_ERROR ((EFI_STATUS)1)
/* OutputString is the 2nd member; pointer size differs per arch. */
#ifdef _WIN64
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#else
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#endif

#define CALC_EXPECTED_SUM 4950
#define CALC_ITER_COUNT   100

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
    for (int i = 0; i < CALC_ITER_COUNT; i++) sum += i;

    if (sum == CALC_EXPECTED_SUM) {
        output_string(conout, MSG_OK);
        return EFI_SUCCESS;
    }
    output_string(conout, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

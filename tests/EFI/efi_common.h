// Shared EFI type/offset definitions for tests/EFI/*/main.c(pp).
// Only the fields peor's test suite actually touches (ConOut, BootServices,
// AllocatePool) — not a general EDK2 header replacement.
#pragma once

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
typedef unsigned long long UINTN;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET    0x60
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET   0x40
#else
typedef unsigned int EFI_STATUS;
typedef unsigned int UINTN;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET    0x3C
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET   0x2C
#endif

#ifdef __cplusplus
typedef char16_t CHAR16;
#else
typedef unsigned short CHAR16;
#endif

#define EFI_SUCCESS      ((EFI_STATUS)0)
#define EFI_LOAD_ERROR   ((EFI_STATUS)1)

typedef EFI_STATUS (*EFI_OUTPUT_STRING_FN)(void *conout, const CHAR16 *str);

// Resolve SystemTable->ConOut->OutputString and print msg through it.
static inline void efi_print(void *system_table, const CHAR16 *msg)
{
    void *const conout = *(void **)(((unsigned char *)system_table) + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    EFI_OUTPUT_STRING_FN print =
        *(EFI_OUTPUT_STRING_FN *)(((unsigned char *)conout) + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);
    print(conout, msg);
}

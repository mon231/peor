// Test finding the EFI_SYSTEM_TABLE (via efi-print to conout)

#include "../efi_common.h"

static const CHAR16 MSG[] = L"PEOR_EFI_HELLO\r\n";

EFI_STATUS efi_main(void* _, void* system_table)
{
    efi_print(system_table, MSG);
    return EFI_SUCCESS;
}

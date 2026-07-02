// Test trivial shellcode in uefi

#include "../efi_common.h"

EFI_STATUS efi_main(void* _, void* __)
{
    return EFI_SUCCESS;
}

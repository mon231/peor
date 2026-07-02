// Test EFI_BOOT_SERVICES in shellcode

#include "../efi_common.h"

#define EFI_LOADER_DATA  2
#define ALLOC_SIZE       64
#define ALLOC_MAGIC      66

EFI_STATUS efi_main(void* _, void* system_table)
{
    void* boot_services = *(void**)(((unsigned char*)system_table) + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET);

    typedef EFI_STATUS (*ALLOCATE_POOL_FN)(int pool_type, UINTN size, void** buff);
    ALLOCATE_POOL_FN allocate_pool = *(ALLOCATE_POOL_FN*)(((unsigned char*)boot_services) + EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET);

    unsigned char* buff = 0;
    if (allocate_pool(EFI_LOADER_DATA, ALLOC_SIZE, (void**)&buff) != EFI_SUCCESS || !buff)
    {
        return EFI_LOAD_ERROR;
    }

    buff[0] = ALLOC_MAGIC;
    if (buff[0] != ALLOC_MAGIC)
    {
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}

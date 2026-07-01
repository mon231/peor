// Test EFI_BOOT_SERVICES in shellcode

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
typedef unsigned long long UINTN;
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET  0x60
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET 0x40
#else
typedef unsigned int EFI_STATUS;
typedef unsigned int UINTN;
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET  0x3C
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET 0x2C
#endif

#define EFI_SUCCESS      ((EFI_STATUS)0)
#define EFI_LOAD_ERROR   ((EFI_STATUS)1)
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

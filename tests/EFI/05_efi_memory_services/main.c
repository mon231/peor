/*
 * EFI memory services test: calls AllocatePool from EFI_BOOT_SERVICES,
 * writes ALLOC_MAGIC (66) to the allocated buffer, reads it back and
 * returns EFI_SUCCESS on match.
 *
 * Supports x64 (PE32+) and x86 (PE32).
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -nostdlib -nodefaultlibs -nostartfiles \
 *     -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -Wl,-e,efi_main -Wl,--subsystem,efi_application \
 *     -o 05_efi_memory_services.efi main.c
 */

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
typedef unsigned long long UINTN;

/* EFI_SYSTEM_TABLE offsets (x64, 64-bit pointers, UEFI spec 2.x) */
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET  0x60

/* EFI_BOOT_SERVICES.AllocatePool offset (x64):
 * Header(24) + RaiseTpl(8) + RestoreTpl(8) + AllocatePages(8) + FreePages(8) +
 * GetMemoryMap(8) = 24+40 = 0x40 */
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET 0x40
#else
typedef unsigned int EFI_STATUS;
typedef unsigned int UINTN;

/* EFI_SYSTEM_TABLE offsets (x86, 32-bit pointers) */
#define EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET  0x3C

/* EFI_BOOT_SERVICES.AllocatePool offset (x86):
 * Header(24) + RaiseTpl(4) + RestoreTpl(4) + AllocatePages(4) + FreePages(4) +
 * GetMemoryMap(4) = 24+20 = 0x2C */
#define EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET 0x2C
#endif

#define EFI_SUCCESS      ((EFI_STATUS)0)
#define EFI_LOAD_ERROR   ((EFI_STATUS)1)
#define EFI_LOADER_DATA  2
#define ALLOC_SIZE       64
#define ALLOC_MAGIC      66

EFI_STATUS efi_main(void *image_handle, void *system_table) {
    (void)image_handle;

    void *boot_services = *(void **)((unsigned char *)system_table
                                     + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET);

    typedef EFI_STATUS (*ALLOCATE_POOL_FN)(int pool_type, UINTN size, void **buf);
    ALLOCATE_POOL_FN allocate_pool = *(ALLOCATE_POOL_FN *)((unsigned char *)boot_services
                                     + EFI_BOOT_SERVICES_ALLOCATE_POOL_OFFSET);

    unsigned char *buf = 0;
    EFI_STATUS st = allocate_pool(EFI_LOADER_DATA, ALLOC_SIZE, (void **)&buf);
    if (st != EFI_SUCCESS || !buf)
        return EFI_LOAD_ERROR;

    buf[0] = ALLOC_MAGIC;
    if (buf[0] != ALLOC_MAGIC)
        return EFI_LOAD_ERROR;

    return EFI_SUCCESS;
}

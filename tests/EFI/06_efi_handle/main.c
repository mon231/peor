// Test that peor's EFI entrypoint resolver passes a real, registered EFI_HANDLE
// as ImageHandle - not NULL - by exercising a boot service that validates it.

#include "../efi_common.h"

typedef EFI_STATUS (*PROTOCOLS_PER_HANDLE_FN)(void* handle, void*** proto_buf, UINTN* proto_count);

EFI_STATUS efi_main(void* handle, void* system_table)
{
    void* boot_services = *(void**)(((unsigned char*)system_table) + EFI_SYSTEM_TABLE_BOOT_SERVICES_OFFSET);
    PROTOCOLS_PER_HANDLE_FN protocols_per_handle =
        *(PROTOCOLS_PER_HANDLE_FN*)(((unsigned char*)boot_services) + EFI_BOOT_SERVICES_PROTOCOLS_PER_HANDLE_OFFSET);

    // A NULL handle must be rejected by firmware - proves the call genuinely
    // requires a valid, registered EFI_HANDLE rather than accepting any pointer.
    void** null_proto_buf = 0;
    UINTN null_proto_count = 0;
    if (protocols_per_handle((void*)0, &null_proto_buf, &null_proto_count) == EFI_SUCCESS)
    {
        return EFI_LOAD_ERROR;
    }

    // The handle peor resolved and passed to efi_main must be accepted.
    void** proto_buf = 0;
    UINTN proto_count = 0;
    if (handle == 0
        || protocols_per_handle(handle, &proto_buf, &proto_count) != EFI_SUCCESS
        || proto_count == 0)
    {
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}

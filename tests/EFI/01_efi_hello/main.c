// Test trivial shellcode in uefi

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#else
typedef unsigned int EFI_STATUS;
#endif

#define EFI_SUCCESS ((EFI_STATUS)0)

EFI_STATUS efi_main(void* _, void* __)
{
    return EFI_SUCCESS;
}

//Test finding the EFI_SYSTEM_TABLE (via efi-print to conout)

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#else
typedef unsigned int EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#endif

typedef unsigned short CHAR16;
#define EFI_SUCCESS ((EFI_STATUS)0)

#ifdef _WIN64
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFFSET 0x08
#else
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFFSET 0x04
#endif

static const CHAR16 MSG[] = L"PEOR_EFI_HELLO\r\n";

EFI_STATUS efi_main(void* _, void *system_table)
{
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);

    void* const conout = *(void**)(((unsigned char*)system_table) + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN print = *(OUTPUT_FN*)(((unsigned char*)conout) + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFFSET);

    print(conout, MSG);
    return EFI_SUCCESS;
}

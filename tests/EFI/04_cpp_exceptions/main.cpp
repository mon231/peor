// Test cpp exceptions in uefi shellcode (!!!)

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#else
typedef unsigned int EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#endif

typedef unsigned short CHAR16;
#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_LOAD_ERROR ((EFI_STATUS)1)

#define MAGIC_VALUE 0x5ECC

struct PeorEfiException
{
    int code;
};

static const CHAR16 MSG_OK[] = L"PEOR_CPP_EH_OK\r\n";
static const CHAR16 MSG_FAIL[] = L"PEOR_CPP_EH_FAIL\r\n";

extern "C" EFI_STATUS efi_main(void* _, void* system_table)
{
    int caught_code = 0;
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);

    void* const conout = *(void**)(((unsigned char*)system_table) + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN print = *(OUTPUT_FN*)(((unsigned char*)conout) + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);

    try
    {
        throw PeorEfiException{MAGIC_VALUE};
    }
    catch (const PeorEfiException& e)
    {
        caught_code = e.code;
    }
    catch (...)
    {
        caught_code = -1;
    }

    if (caught_code == MAGIC_VALUE) {
        print(conout, MSG_OK);
        return EFI_SUCCESS;
    }

    print(conout, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

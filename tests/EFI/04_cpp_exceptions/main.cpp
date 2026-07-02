// Test cpp exceptions in uefi shellcode (!!!)

#include "../efi_common.h"

#define MAGIC_VALUE 0x5ECC

struct PeorEfiException
{
    int code;
};

static const CHAR16 MSG_OK[] = u"PEOR_CPP_EH_OK\r\n";
static const CHAR16 MSG_FAIL[] = u"PEOR_CPP_EH_FAIL\r\n";

extern "C" EFI_STATUS efi_main(void* _, void* system_table)
{
    int caught_code = 0;

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
        efi_print(system_table, MSG_OK);
        return EFI_SUCCESS;
    }

    efi_print(system_table, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

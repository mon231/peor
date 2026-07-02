// Test functions in efi shellcode

#include "../efi_common.h"

#define CALC_EXPECTED_SUM 4950
#define CALC_ITER_COUNT   100

static const CHAR16 MSG_OK[] = L"PEOR_4950\r\n";
static const CHAR16 MSG_FAIL[] = L"PEOR_CALC_FAIL\r\n";

int calc()
{
    int sum = 0;
    for (int i = 0; i < CALC_ITER_COUNT; i++)
    {
        sum += i;
    }

    return sum;
}

EFI_STATUS efi_main(void* _, void* system_table)
{
    if (calc() == CALC_EXPECTED_SUM)
    {
        efi_print(system_table, MSG_OK);
        return EFI_SUCCESS;
    }

    efi_print(system_table, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

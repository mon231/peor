// Test functions in efi shellcode

#ifdef _WIN64
typedef unsigned long long EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x40
#else
typedef unsigned int EFI_STATUS;
#define EFI_SYSTEM_TABLE_CONOUT_OFFSET           0x2C
#endif

typedef unsigned short CHAR16;

#define EFI_SUCCESS    ((EFI_STATUS)0)
#define EFI_LOAD_ERROR ((EFI_STATUS)1)

#ifdef _WIN64
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x08
#else
#define EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF 0x04
#endif

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
    typedef EFI_STATUS (*OUTPUT_FN)(void *, const CHAR16 *);

    void* const conout = *(void**)(((unsigned char*)system_table) + EFI_SYSTEM_TABLE_CONOUT_OFFSET);
    OUTPUT_FN print = *(OUTPUT_FN*)(((unsigned char*)conout) + EFI_SIMPLE_TEXT_OUTPUT_OUTPUT_STRING_OFF);

    if (calc() == CALC_EXPECTED_SUM)
    {
        print(conout, MSG_OK);
        return EFI_SUCCESS;
    }

    print(conout, MSG_FAIL);
    return EFI_LOAD_ERROR;
}

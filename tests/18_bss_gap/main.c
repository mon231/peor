// Test shellcode has the bss zero-initialized
#define BSS_ARRAY_SIZE (4096)
#define PROGRAM_EXIT_CODE (88)

static volatile int g_arr[BSS_ARRAY_SIZE] = {0};

int main(void)
{
    int sum = 0;

    for (int i = 0; i < BSS_ARRAY_SIZE; i++)
    {
        sum += g_arr[i];
    }

    return (sum == 0) ? PROGRAM_EXIT_CODE : 0;
}

// Importless, custom entrypoint, no CRT.
// Global pointer to another global forces a relocation entry (absolute address fixup).
// DYNAMICBASE (/RandomizedBaseAddress) ensures the .reloc section is emitted.

static int g_value = 42;
static int g_array[4] = {10, 20, 30, 40};

// relocs-cause: holds absolute address of g_value
static int* g_ptr = &g_value;

static int add(int a, int b)
{
    return a + b;
}

static int accumulate(int* arr, int len)
{
    int sum = 0;

    for (int i = 0; i < len; ++i)
    {
        sum = add(sum, arr[i]);
    }

    return sum;
}

int main(void)
{
    *g_ptr = accumulate(g_array, 4);
    g_array[0] = *g_ptr + g_array[1];
    g_value = g_array[0] - g_array[2];
    return g_value;
}

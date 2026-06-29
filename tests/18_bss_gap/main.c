#define BSS_ARRAY_SIZE 4096
#define RETURN_ALL_ZERO 88

static int g_arr[BSS_ARRAY_SIZE] = {0}; /* zero-initialized by C spec — lives in BSS */

int main(void) {
    int sum = 0;
    int i;
    for (i = 0; i < BSS_ARRAY_SIZE; i++)
        sum += g_arr[i];
    return (sum == 0) ? RETURN_ALL_ZERO : 0;
}

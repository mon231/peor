// CRT entrypoint (mainCRTStartup calls main). Uses srand/rand/printf from the CRT.
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(void)
{
    srand((unsigned int)time(NULL));
    printf("Random: %d\n", rand());
    return 0;
}

#include <stdio.h>
#include <unistd.h>
int main(void) {
    int n = 0;
    while (1) {
        printf("tick %d\n", n++);
        fflush(stdout);
        sleep(2);
    }
    return 0;
}

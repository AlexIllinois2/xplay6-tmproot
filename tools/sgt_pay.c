// tools/sgt_pay.c -- payload for sugate_probe: prints RAN on stderr and exits 0.
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    dprintf(2, "RAN\n");
    _exit(0);
}

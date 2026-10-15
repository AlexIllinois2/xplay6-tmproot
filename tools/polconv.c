/* Run ON DEVICE. /sys/fs/selinux/policy hands back a *sepol image* (magic f97cff8c,
 * "SE Linux", kern vers 30) but /sys/fs/selinux/load wants the *raw kernel policy*
 * (magic 0x003f00dd) -- measured: writing the dump back failed with rc=1. Upstream
 * libsepol on the host cannot parse this era's avtab at all (invalid specifier), so
 * the conversion has to be done by the device's own libsepol, which is period-correct.
 *
 * No build-time dependency on libsepol: the symbols are dlopen'd from the device.
 *
 * usage: polconv <in-image> <out-raw>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

typedef void *sepol_handle_t;
typedef void *sepol_policy_file_t;
typedef void *sepol_policydb_t;

static void *h_sepol;
static long (*api_handle_create)(void);
static long (*api_handle_destroy)(long);
static long (*api_pf_create)(void **);
static long (*api_pf_set_handle)(long, long);
static long (*api_pf_set_fp)(long, void *);
static long (*api_db_create)(void **);
static long (*api_db_read)(long, long);
static long (*api_db_write)(long, long);
static long (*api_db_mls_enabled)(long);
static int mls;

static int resolve(void)
{
    const char *paths[] = { "/system/lib64/libsepol.so", "/system/lib/libsepol.so", NULL };
    int i;

    for (i = 0; paths[i]; i++) {
        h_sepol = dlopen(paths[i], RTLD_NOW);
        if (h_sepol != NULL) {
            printf("using %s\n", paths[i]);
            break;
        }
        printf("dlopen %s: %s\n", paths[i], dlerror());
    }
    if (h_sepol == NULL)
        return -1;
#define S(v, n) do { *(void **)&api_##v = dlsym(h_sepol, n); \
        if (api_##v == NULL) { printf("missing symbol %s\n", n); return -1; } } while (0)
    S(handle_create, "sepol_handle_create");
    S(pf_create, "sepol_policy_file_create");
    S(pf_set_handle, "sepol_policy_file_set_handle");
    S(pf_set_fp, "sepol_policy_file_set_fp");
    S(db_create, "sepol_policydb_create");
    S(db_read, "sepol_policydb_read");
    S(db_write, "sepol_policydb_write");
    S(db_mls_enabled, "sepol_policydb_mls_enabled");
#undef S
    return 0;
}

int main(int argc, char **argv)
{
    long h, pf_in, pf_out, db;
    void *p = NULL;
    FILE *in, *out;
    int rc;

    if (argc < 3) {
        printf("usage: polconv <in-image> <out-raw>\n");
        return 2;
    }
    if (resolve() != 0)
        return 3;
    in = fopen(argv[1], "rb");
    if (in == NULL) {
        perror("open input");
        return 4;
    }
    out = fopen(argv[2], "wb");
    if (out == NULL) {
        perror("open output");
        return 5;
    }
    h = api_handle_create();
    api_pf_create(&p); pf_in = (long)p;
    api_pf_set_handle(pf_in, h);
    api_pf_set_fp(pf_in, in);
    api_db_create(&p); db = (long)p;
    rc = api_db_read(db, pf_in);
    printf("policydb_read rc=%d (0=ok)\n", rc);
    if (rc != 0)
        return 6;
    mls = (int)api_db_mls_enabled(db);
    printf("mls_enabled=%d\n", mls);
    api_pf_create(&p); pf_out = (long)p;
    api_pf_set_handle(pf_out, h);
    api_pf_set_fp(pf_out, out);
    rc = api_db_write(db, pf_out);
    printf("policydb_write rc=%d (0=ok)\n", rc);
    fflush(out);
    fclose(out);
    fclose(in);
    return rc == 0 ? 0 : 7;
}

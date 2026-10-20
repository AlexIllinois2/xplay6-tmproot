/* tools/calget.c -- read back live speaker-protection calibration from /dev/msm_audio_cal.
 * GET(204) only: never ALLOCATE/PREPARE/SET/POST.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "msm_audio_calibration.h"

#define SENT 0xAAu

enum { K_FB, K_TH, K_EX, K_RAW };

struct arm {
	const char *tag;
	const char *name;
	int32_t type;
	size_t cts;
	int kind;
};

static const struct arm arms[] = {
	{ "fb", "AFE_FB_SPKR_PROT / status",
	  AFE_FB_SPKR_PROT_CAL_TYPE,
	  sizeof(struct audio_cal_type_fb_spk_prot_status), K_FB },
	{ "th", "AFE_FB_SPKR_PROT_TH_VI / param",
	  AFE_FB_SPKR_PROT_TH_VI_CAL_TYPE,
	  sizeof(struct audio_cal_type_sp_th_vi_param), K_TH },
	{ "ex", "AFE_FB_SPKR_PROT_EX_VI / param",
	  AFE_FB_SPKR_PROT_EX_VI_CAL_TYPE,
	  sizeof(struct audio_cal_type_sp_ex_vi_param), K_EX },
	/* driver accepts this size (<= its cap) but the callback's own
	 * data_size != sizeof(*cal_data) guard must refuse it: proves a WRITTEN verdict
	 * above really came from the callback and not from an echo. */
	{ "fbwrong", "CTRL AFE_FB_SPKR_PROT / cfg size",
	  AFE_FB_SPKR_PROT_CAL_TYPE,
	  sizeof(struct audio_cal_type_fb_spk_prot_cfg), K_FB },
	/* no registrant in this build implements get_cal for AFE_TOPOLOGY */
	{ "ctrl", "CTRL AFE_TOPOLOGY / own size",
	  AFE_TOPOLOGY_CAL_TYPE,
	  sizeof(struct audio_cal_type_afe_top), K_RAW },
};

#define NARMS ((int)(sizeof arms / sizeof *arms))

static void q(const char *label, int32_t v, int bits)
{
	printf("%s=%d (0x%08x)", label, v, (unsigned)v);
	if (v >= 0 && v < (1 << 20))
		printf(" =%.4f", (double)v / (double)(1u << bits));
	printf("  ");
}

static void decode(int kind, const int32_t *i)
{
	switch (kind) {
	case K_FB:
		q("r0_spk1_q24", i[0], 24);
		q("r0_spk2_q24", i[1], 24);
		printf("status=%d\n", i[2]);
		break;
	case K_TH:
		q("r_dc_q24_1", i[0], 24);
		q("r_dc_q24_2", i[1], 24);
		printf("\n    ");
		q("temp_q22_1", i[2], 22);
		q("temp_q22_2", i[3], 22);
		printf("status=[%d,%d]\n", i[4], i[5]);
		break;
	case K_EX:
		q("freq_q20_1", i[0], 20);
		q("freq_q20_2", i[1], 20);
		printf("\n    ");
		q("resis_q24_1", i[2], 24);
		q("resis_q24_2", i[3], 24);
		printf("\n    ");
		q("qmct_q24_1", i[4], 24);
		q("qmct_q24_2", i[5], 24);
		printf("status=[%d,%d,%d,%d]\n", i[6], i[7], i[8], i[9]);
		break;
	default:
		printf("\n");
	}
}

static int one(int fd, const struct arm *a, uint8_t *buf)
{
	struct audio_cal_header *h = (struct audio_cal_header *)buf;
	int32_t *info;
	size_t payload;
	int rc, i, touched = 0;

	memset(buf, 0, 512);
	h->data_size = (int32_t)(sizeof(struct audio_cal_header) + a->cts);
	h->version = VERSION_0_0;
	h->cal_type = a->type;
	h->cal_type_size = (int32_t)a->cts;
	payload = a->cts - sizeof(struct audio_cal_type_basic);
	memset(buf + 32, SENT, payload);

	errno = 0;
	rc = ioctl(fd, AUDIO_GET_CALIBRATION, buf);
	for (i = 0; (size_t)i < payload; i++)
		if (buf[32 + i] != SENT)
			touched++;

	printf("%-38s type=%2zu cts=%2zu data_size=%3zu rc=%d errno=%d(%s) "
	       "hdr{buf=%d cal_size=%d mem=%d} written=%d/%zu\n",
	       a->name, (size_t)a->type, a->cts, (size_t)h->data_size, rc, errno,
	       rc ? strerror(errno) : "ok",
	       *(int32_t *)(buf + 20), *(int32_t *)(buf + 24),
	       *(int32_t *)(buf + 28), touched, payload);
	if (rc)
		return rc;
	printf("    raw:");
	for (i = 0; (size_t)i < payload; i++)
		printf(" %02x", buf[32 + i]);
	printf("\n");
	if (touched) {
		info = (int32_t *)(buf + 32);
		printf("    ");
		decode(a->kind, info);
	} else {
		printf("    untouched (callback wrote nothing)\n");
	}
	return rc;
}

int main(int argc, char **argv)
{
	static uint8_t buf[512] __attribute__((aligned(64)));
	int fd, i, n = NARMS, reps = 1, gap_ms = 0;
	const char *want = argc > 1 ? argv[1] : "all";

	if (argc > 2)
		reps = atoi(argv[2]);
	if (argc > 3)
		gap_ms = atoi(argv[3]);

	for (i = 0; i < n; i++)
		printf("arm %d %-38s sizeof(cal_type struct)=%zu\n",
		       i, arms[i].name, arms[i].cts);

	fd = open("/dev/msm_audio_cal", O_RDWR);
	if (fd < 0) {
		printf("open failed errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("open ok fd=%d reps=%d gap_ms=%d\n", fd, reps, gap_ms);

	while (reps-- > 0) {
		printf("--- pass start %ld\n", (long)time(NULL));
		for (i = 0; i < n; i++)
			if (strcmp(want, "all") == 0 ||
			    strcmp(want, arms[i].tag) == 0)
				one(fd, &arms[i], buf);
		if (reps > 0 && gap_ms > 0) {
			struct timespec ts;
			ts.tv_sec = gap_ms / 1000;
			ts.tv_nsec = (long)(gap_ms % 1000) * 1000000L;
			nanosleep(&ts, NULL);
		}
	}

	printf("close fd=%d (last close makes audio_cal_release run dealloc_all_clients)\n",
	       fd);
	close(fd);
	return 0;
}

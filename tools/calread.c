/* tools/calread.c -- read ONE calibration block back from /dev/msm_audio_cal, using the
 * driver's own six-step contract (ALLOCATE 200 / PREPARE 202 / GET 204 / DEALLOCATE 201).
 *
 * READ ONLY on purpose: SET(203)/POST(205) and every SET_RTAC_* are never sent here.  The
 * speaker-protection limits (audio_cal_info_spk_prot_cfg) live behind the same structures,
 * so a tool that could write them should not be the first thing pointed at a live DSP.
 *
 * Layouts are transcribed from fw/audio-cal/msm_audio_calibration.h (this CAF branch):
 *   audio_cal_header     { data_size, version, cal_type, cal_type_size }        16 B
 *   audio_cal_type_header{ version, buffer_number }                              8 B
 *   audio_cal_data       { cal_size, mem_handle }                                8 B
 *   audio_cal_type_basic = type_header + data                                   16 B
 *   audio_cal_basic      = header + type_basic                                  32 B
 * Driver checks: data_size in [sizeof(audio_cal_basic), MAX_IOCTL_CMD_SIZE=512];
 * cal_type in [0,45); cal_type_size >= 16 and <= its own per-type table; buffer_number >= 0.
 * With mem_handle == 0 the payload is inline: data_size = 32 + cal_size.
 *
 * usage: calread [cal_type] [cal_size]      (defaults 28 = ADM_RTAC_INFO_CAL_TYPE, 256)
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CAL_IOCTL_MAGIC 'a'
/* The kernel's own macros, not a hand-rolled encoding: my first version packed the
 * direction at bit 29 (real _IOC_DIRSHIFT is 30) and every step came back EFAULT, which in
 * this driver means "ioctl not found" rather than a bad pointer. */
#define CMD_ALLOCATE		_IOWR(CAL_IOCTL_MAGIC, 200, void *)
#define CMD_DEALLOCATE		_IOWR(CAL_IOCTL_MAGIC, 201, void *)
#define CMD_PREPARE		_IOWR(CAL_IOCTL_MAGIC, 202, void *)
#define CMD_GET			_IOWR(CAL_IOCTL_MAGIC, 204, void *)
#define CMD_GET_RTAC_ADM_INFO	_IOR(CAL_IOCTL_MAGIC, 207, void *)

struct audio_cal_header {
	int32_t data_size;
	int32_t version;
	int32_t cal_type;
	int32_t cal_type_size;
};

struct audio_cal_type_header {
	int32_t version;
	int32_t buffer_number;
};

struct audio_cal_data {
	int32_t cal_size;
	int32_t mem_handle;
};

struct audio_cal_type_basic {
	struct audio_cal_type_header cal_hdr;
	struct audio_cal_data cal_data;
};

/* header + type_basic + inline payload */
struct pkt {
	struct audio_cal_header hdr;
	struct audio_cal_type_basic cal_type;
	uint8_t buf[512];
};

static const char *cal_type_name(int t)
{
	static const char *n[] = {
		"CVP_VOC_RX_TOPOLOGY", "CVP_VOC_TX_TOPOLOGY", "CVP_VOCPROC_STATIC",
		"CVP_VOCPROC_DYNAMIC", "CVS_VOCSTRM_STATIC", "CVP_VOCDEV_CFG",
	};
	if (t >= 0 && t < (int)(sizeof n / sizeof *n))
		return n[t];
	switch (t) {
	case 23: return "AFE_TOPOLOGY";
	case 28: return "ADM_RTAC_INFO";
	case 29: return "VOICE_RTAC_INFO";
	case 30: return "ADM_RTAC_APR";
	case 31: return "ASM_RTAC_APR";
	case 32: return "VOICE_RTAC_APR";
	case 40: return "ADM_RTAC_AUDVOL";
	default: return "cal_type?";
	}
}

int main(int argc, char **argv)
{
	struct pkt p;
	int type = argc > 1 ? atoi(argv[1]) : 28;
	int csize = argc > 2 ? atoi(argv[2]) : 256;
	int fd, i, rc, cmd;

	if (csize < 0 || csize > (int)sizeof p.buf) {
		printf("cal_size out of range\n");
		return 2;
	}
	fd = open("/dev/msm_audio_cal", O_RDWR);
	if (fd < 0) {
		printf("open /dev/msm_audio_cal: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}
	printf("fd=%d type=%d(%s) cal_size=%d\n", fd, type, cal_type_name(type), csize);

	memset(&p, 0, sizeof p);
	p.hdr.data_size = (int32_t)(sizeof(struct audio_cal_header) + sizeof(struct audio_cal_type_basic) + csize);
	p.hdr.version = 0;
	p.hdr.cal_type = type;
	p.hdr.cal_type_size = (int32_t)sizeof(struct audio_cal_type_basic);
	p.cal_type.cal_hdr.version = 0;
	p.cal_type.cal_hdr.buffer_number = 0;
	p.cal_type.cal_data.cal_size = csize;
	p.cal_type.cal_data.mem_handle = 0;

	for (i = 0; i < 3; i++) {
		cmd = i == 0 ? (int)CMD_ALLOCATE : (i == 1 ? (int)CMD_PREPARE : (int)CMD_GET);
		errno = 0;
		rc = ioctl(fd, (unsigned long)cmd, &p);
		printf("step %d ioctl cmd=%#x rc=%d errno=%d (%s)  seen cal_size=%d\n",
		       i, (unsigned)cmd, rc, errno, rc ? strerror(errno) : "ok",
		       p.cal_type.cal_data.cal_size);
		if (rc != 0)
			break;
		if (i == 2) {
			int n = p.cal_type.cal_data.cal_size;
			if (n < 0 || n > csize)
				n = csize;
			printf("payload first %d bytes:\n", n);
			for (int off = 0; off < n; off += 16) {
				printf("  %04x:", off);
				for (int k = off; k < off + 16 && k < n; k++)
					printf(" %02x", p.buf[k]);
				printf("\n");
			}
		}
	}
	errno = 0;
	rc = ioctl(fd, (unsigned long)CMD_DEALLOCATE, &p);
	printf("dealloc rc=%d errno=%d\n", rc, errno);
	close(fd);
	return 0;
}

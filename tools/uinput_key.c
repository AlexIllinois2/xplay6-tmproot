/* Wake/unlock the device from the root channel by building a real KEYBOARD input device on
 * /dev/uinput and sending one key.  The framework's injection API is not usable here: as uid 2000
 * the InputDispatcher refuses cross-uid injection (ledger 607), the daemon's exec environment cannot
 * run app_process clients at all (`settings put` dies with a NullPointerException on
 * IActivityManager.getContentProviderExternal, measured 2026-10-20), and `input keyevent` is such a
 * client.  What DOES work is a device: InputReader attaches /dev/input/* nodes and PhoneWindowManager
 * consumes their KEY_POWER, which is how tools/uinput_tap gets clicks honoured (ledger 611-612).
 *
 * Kernel 3.18 has no UI_DEV_SETUP (added in 4.5), so the device description is written as a
 * uinput_user_dev record and only then created -- same shape as uinput_tap.c.
 *
 * usage: uinput_key <keycode>      (e.g. 116 = KEY_POWER, 82 = KEY_MENU, 224 = KEY_WAKEUP)
 */
#include <linux/input.h>
#include <linux/uinput.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static void emit(int fd, int type, int code, int value)
{
	struct input_event ev;

	memset(&ev, 0, sizeof ev);
	ev.type = type;
	ev.code = code;
	ev.value = value;
	if (write(fd, &ev, sizeof ev) < 0)
		printf("uinput_key: emit %d/%d/%d failed errno=%d\n", type, code, value, errno);
}

int main(int argc, char **argv)
{
	struct uinput_user_dev dev;
	int fd, code;

	if (argc < 2) {
		printf("usage: uinput_key <keycode>   (116=POWER 82=MENU 224=WAKEUP 102=HOME)\n");
		return 2;
	}
	code = atoi(argv[1]);
	if (code <= 0 || code > 255) {
		printf("uinput_key: keycode %d out of range -- refusing\n", code);
		return 2;
	}
	fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		printf("uinput_key: REFUSE: /dev/uinput errno=%d (%s) -- needs root\n", errno, strerror(errno));
		return 1;
	}
	if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 || ioctl(fd, UI_SET_KEYBIT, code) < 0) {
		printf("uinput_key: REFUSE: cannot enable key %d errno=%d (%s)\n", code, errno, strerror(errno));
		close(fd);
		return 1;
	}
	memset(&dev, 0, sizeof dev);
	snprintf((char *)dev.name, UINPUT_MAX_NAME_SIZE, "xplay6-uinput-key");
	dev.id.bustype = BUS_VIRTUAL;
	dev.id.vendor = 0x1234;
	dev.id.product = 0x1235;
	dev.id.version = 1;
	if (write(fd, &dev, sizeof dev) < 0) {
		printf("uinput_key: REFUSE: uinput_user_dev write errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return 1;
	}
	if (ioctl(fd, UI_DEV_CREATE) < 0) {
		printf("uinput_key: REFUSE: UI_DEV_CREATE errno=%d (%s)\n", errno, strerror(errno));
		close(fd);
		return 1;
	}
	/* InputReader needs more than a poll to attach a freshly created device; 400 ms was measured
	 * NOT enough (ledger 611), so wait before firing the key. */
	usleep(2500000);
	emit(fd, EV_KEY, code, 1);
	emit(fd, EV_SYN, SYN_REPORT, 0);
	usleep(80000);
	emit(fd, EV_KEY, code, 0);
	emit(fd, EV_SYN, SYN_REPORT, 0);
	usleep(1200000);
	printf("uinput_key: sent KEYCODE %d down+up through xplay6-uinput-key\n", code);
	fflush(stdout);
	ioctl(fd, UI_DEV_DESTROY);
	close(fd);
	return 0;
}

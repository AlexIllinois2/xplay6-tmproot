/* tools/uinput_tap.c -- make the kernel hand Android a REAL touchscreen and click through it.

Why this exists when tools/fts_tap.sh already does not work (measured, ledger 604/607):
  writing to /dev/input/event6 with sendevent leaves the input core -- the node accepts the bytes
  (sendevent exits 0) but neither a touch nor a volume key reaches userspace, so the events are being
  dropped between evdev_write and the handlers on this ROM.  This file takes the other door: it asks
  uinput to CREATE a new device, so the events originate from a real driver rather than being
  injected into someone else's node, and InputReader enumerates it through its usual inotify path.

  The device we create is deliberately single-touch Type-A (ABS_X/ABS_Y + BTN_TOUCH +
  INPUT_PROP_DIRECT) with ranges equal to the DISPLAY, not the fts controller's raw 1440x2560 --
  that 4/3 mismatch is what made every remembered pixel coordinate land somewhere else (ledger 604).

Kernel 3.18 has no UI_DEV_SETUP (added in 4.5), so the device description is written as a
uinput_user_dev record and only then created -- using the modern ioctl would silently leave a
nameless device with max=0 and every event out of range.

usage:  uinput_tap <x> <y>            one click, then the device is destroyed
        uinput_tap <x> <y> <ms>       press duration in ms (default 120)
*/
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifndef UI_SET_PROPBIT
#define UI_SET_PROPBIT _IOW(UINPUT_IOCTL_BASE, 170, int)   /* INPUT_PROP_DIRECT: without it Android
                                                             may class this as a touchpad */
#endif

#define XMAX 1079
#define YMAX 1919

static int emit(int fd, int type, int code, int val)
{
    struct input_event ev;

    memset(&ev, 0, sizeof ev);
    ev.type = (short)type;
    ev.code = (short)code;
    ev.value = val;
    if (write(fd, &ev, sizeof ev) < 0) {
        printf("emit %d/%d/%d failed errno=%d\n", type, code, val, errno);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct uinput_user_dev udev;
    int fd, ms = 120, x, y, drag = 0, x2 = 0, y2 = 0, steps = 12, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "--drag")) {
        /* --drag x1 y1 x2 y2 [steps]: the keyguard is dismissed by a slide, not a click, and the
         * panel needs the slide to come from a device the framework trusts (ledger 619). */
        if (argc < 6) {
            printf("usage: uinput_tap --drag <x1> <y1> <x2> <y2> [steps]\n");
            return 2;
        }
        drag = 1;
        x = atoi(argv[2]);
        y = atoi(argv[3]);
        x2 = atoi(argv[4]);
        y2 = atoi(argv[5]);
        if (argc > 6)
            steps = atoi(argv[6]);
        if (steps < 2)
            steps = 2;
    } else if (argc >= 3) {
        x = atoi(argv[1]);
        y = atoi(argv[2]);
        if (argc > 3)
            ms = atoi(argv[3]);
    } else {
        printf("usage: uinput_tap <x> <y> [press-ms]   OR   uinput_tap --drag <x1> <y1> <x2> <y2> [steps]"
               "  (display space, %d..%d x %d..%d)\n", 0, XMAX, 0, YMAX);
        return 2;
    }
    /* refuse rather than click an unrelated place: this is the exact mistake the evdev route made */
    if (x < 0 || x > XMAX || y < 0 || y > YMAX || x2 < 0 || x2 > XMAX || y2 < 0 || y2 > YMAX) {
        printf("REFUSE: (%d,%d)->(%d,%d) outside the display space 0..%d x 0..%d -- nothing sent\n",
               x, y, x2, y2, XMAX, YMAX);
        return 1;
    }

    fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        printf("REFUSE: /dev/uinput errno=%d (%s) -- needs root\n", errno, strerror(errno));
        return 1;
    }
    /* INPUT_PROP_DIRECT -- the single property that makes a pointing device a SCREEN touch. */
    if (ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT) < 0)
        printf("NOTE: UI_SET_PROPBIT errno=%d -- device will be created without INPUT_PROP_DIRECT\n",
               errno);
    if (ioctl(fd, UI_SET_EVBIT, EV_KEY) < 0 || ioctl(fd, UI_SET_KEYBIT, BTN_TOUCH) < 0
        || ioctl(fd, UI_SET_EVBIT, EV_ABS) < 0
        || ioctl(fd, UI_SET_ABSBIT, ABS_X) < 0 || ioctl(fd, UI_SET_ABSBIT, ABS_Y) < 0) {
        printf("REFUSE: UI_SET_* failed errno=%d -- no device created\n", errno);
        close(fd);
        return 1;
    }
    memset(&udev, 0, sizeof udev);
    snprintf(udev.name, sizeof udev.name, "xplay6-uinput-tap");
    udev.id.bustype = BUS_VIRTUAL;
    udev.id.vendor = 0x1;
    udev.id.product = 0x1;
    udev.id.version = 1;
    udev.absmax[ABS_X] = XMAX;
    udev.absmax[ABS_Y] = YMAX;
    udev.absmin[ABS_X] = 0;
    udev.absmin[ABS_Y] = 0;
    udev.absfuzz[ABS_X] = 0;
    udev.absflat[ABS_X] = 0;
    udev.absfuzz[ABS_Y] = 0;
    udev.absflat[ABS_Y] = 0;
    if (write(fd, &udev, sizeof udev) < 0) {
        printf("REFUSE: uinput_user_dev write failed errno=%d -- no device created\n", errno);
        close(fd);
        return 1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        printf("REFUSE: UI_DEV_CREATE failed errno=%d\n", errno);
        close(fd);
        return 1;
    }
    /* InputReader learns about a new node through inotify + a re-scan; measured 400 ms is NOT
       enough -- the first version of this tool clicked before the reader had attached (ledger 611). */
    usleep(2500000);
    if (drag) {
        printf("drag (%d,%d)->(%d,%d) in %d steps\n", x, y, x2, y2, steps);
        if (emit(fd, EV_ABS, ABS_X, x) < 0 || emit(fd, EV_ABS, ABS_Y, y) < 0
            || emit(fd, EV_KEY, BTN_TOUCH, 1) < 0 || emit(fd, EV_SYN, SYN_REPORT, 0) < 0)
            return 1;
        for (i = 1; i <= steps; i++) {
            if (emit(fd, EV_ABS, ABS_X, x + (x2 - x) * i / steps) < 0
                || emit(fd, EV_ABS, ABS_Y, y + (y2 - y) * i / steps) < 0
                || emit(fd, EV_SYN, SYN_REPORT, 0) < 0)
                return 1;
            usleep(20000);
        }
    } else {
        printf("click (%d,%d) for %d ms\n", x, y, ms);
        if (emit(fd, EV_ABS, ABS_X, x) < 0 || emit(fd, EV_ABS, ABS_Y, y) < 0
            || emit(fd, EV_KEY, BTN_TOUCH, 1) < 0 || emit(fd, EV_SYN, SYN_REPORT, 0) < 0)
            return 1;
        usleep((useconds_t)ms * 1000);
    }
    if (emit(fd, EV_KEY, BTN_TOUCH, 0) < 0 || emit(fd, EV_SYN, SYN_REPORT, 0) < 0)
        return 1;
    usleep(1000000);          /* let the up event drain before the device goes away */
    ioctl(fd, UI_DEV_DESTROY);
    close(fd);
    printf("UINPUT_TAP_DONE\n");
    return 0;
}

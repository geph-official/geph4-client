/*
 * Since the rust ioctl bindings don't have all the structures and constants,
 * it's easier to just write the thing in C and link it in.
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

/**
 * fd ‒ the fd to turn into TUN or TAP.
 * name ‒ the name to use. If empty, kernel will assign something by itself.
 *   Must be buffer with capacity at least 33.
 * mode ‒ 1 = TUN, 2 = TAP.
 * packet_info ‒ if packet info should be provided, if the given value is 0 it will not prepend packet info.
 */
int tun_setup(int fd, unsigned char *name) {
	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
 

	// Leave one for terminating '\0'. No idea if it is needed, didn't find
	// it in the docs, but assuming the worst.
	strncpy(ifr.ifr_name, (char *)name, IFNAMSIZ - 1);

	int ioresult = ioctl(fd, TUNSETIFF, &ifr);
	if (ioresult < 0) {
		return ioresult;
	}
	strncpy((char *)name, ifr.ifr_name, IFNAMSIZ < 32 ? IFNAMSIZ : 32);
	name[32] = '\0';
	return 0;
}

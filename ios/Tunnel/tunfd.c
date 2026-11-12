// Find the utun file descriptor behind NEPacketTunnelFlow (the trick WireGuard's iOS app uses):
// scan the process's descriptors for a kernel-control socket connected to the utun control.
// The iOS SDK does not ship <sys/kern_control.h>, so the two structures and the ioctl are
// declared here (layout from xnu bsd/sys/kern_control.h, stable since 10.x).
#include "tunfd.h"

#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

struct maski_ctl_info {
    u_int32_t ctl_id;
    char ctl_name[96];
};

struct maski_sockaddr_ctl {
    u_char sc_len;
    u_char sc_family;
    u_int16_t ss_sysaddr;
    u_int32_t sc_id;
    u_int32_t sc_unit;
    u_int32_t sc_reserved[5];
};

#define MASKI_CTLIOCGINFO _IOWR('N', 3, struct maski_ctl_info)
#define MASKI_SYSPROTO_CONTROL 2
#define MASKI_UTUN_OPT_IFNAME 2

int maski_find_utun_fd(char *ifname, int ifname_len) {
    struct maski_ctl_info info;
    memset(&info, 0, sizeof info);
    strncpy(info.ctl_name, "com.apple.net.utun_control", sizeof info.ctl_name - 1);
    for (int fd = 0; fd <= 1024; fd++) {
        struct maski_sockaddr_ctl addr;
        socklen_t len = sizeof addr;
        memset(&addr, 0, sizeof addr);
        if (getpeername(fd, (struct sockaddr *)&addr, &len) != 0 || addr.sc_family != AF_SYSTEM) {
            continue;
        }
        if (info.ctl_id == 0 && ioctl(fd, MASKI_CTLIOCGINFO, &info) != 0) {
            continue;
        }
        if (addr.sc_id != info.ctl_id) {
            continue;
        }
        if (ifname && ifname_len > 0) {
            socklen_t l = (socklen_t)ifname_len;
            ifname[0] = 0;
            if (getsockopt(fd, MASKI_SYSPROTO_CONTROL, MASKI_UTUN_OPT_IFNAME, ifname, &l) != 0) {
                ifname[0] = 0;
            }
        }
        return fd;
    }
    return -1;
}

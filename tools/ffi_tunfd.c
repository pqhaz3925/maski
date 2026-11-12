/* Check of the C API in utun-fd mode (as an Apple Network Extension would use it, with the fd behind
 * NEPacketTunnelFlow): open a utun here, hand its fd to maski_start, configure the interface with the
 * address from MASKI_EVENT_CONNECTED, then ping through it. Needs root (utun + ifconfig/route).
 * run: sudo env MASKI_CONFIG='{...}' ./target/apple-linktest/ffi_tunfd */
#include <net/if_utun.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>
#include "maski.h"

static char addr[64];
static atomic_int up;
static void on_event(void *ctx, int32_t kind, const char *json) {
    printf("event %d %s\n", kind, json);
    const char *a = strstr(json, "\"address\":\"");
    if (kind == MASKI_EVENT_CONNECTED && a) { a += 11; memcpy(addr, a, strcspn(a, "\"")); atomic_store(&up, 1); }
}
int main(void) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    struct ctl_info ci = {0};
    strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof ci.ctl_name);
    if (fd < 0 || ioctl(fd, CTLIOCGINFO, &ci) < 0) { perror("utun"); return 1; }
    struct sockaddr_ctl sc = {.sc_len = sizeof sc, .sc_family = AF_SYSTEM, .ss_sysaddr = AF_SYS_CONTROL, .sc_id = ci.ctl_id, .sc_unit = 0};
    if (connect(fd, (struct sockaddr *)&sc, sizeof sc) < 0) { perror("connect utun"); return 1; }
    char name[32]; socklen_t nl = sizeof name;
    getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &nl);
    printf("opened %s fd %d\n", name, fd);
    MaskiHandle *h = maski_start(getenv("MASKI_CONFIG"), fd, NULL, on_event, NULL);
    for (int i = 0; i < 100 && !atomic_load(&up); i++) usleep(50000);
    if (!atomic_load(&up)) return 1;
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ifconfig %s %s 10.90.0.1 mtu 1360 up && route -q -n add -net 10.90.0.0/24 10.90.0.1", name, addr);
    system(cmd);
    int rc = system("ping -c 10 -i 0.2 -q 10.90.0.1");
    MaskiStats s; maski_stats(h, &s);
    printf("ping rc %d; stats tx=%llu rx=%llu\n", rc, s.tx_packets, s.rx_packets);
    maski_stop(h);
    snprintf(cmd, sizeof cmd, "route -q -n delete -net 10.90.0.0/24 10.90.0.1");
    system(cmd);
    close(fd);
    return rc != 0;
}

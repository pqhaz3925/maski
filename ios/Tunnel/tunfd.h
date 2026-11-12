#ifndef MASKI_TUNFD_H
#define MASKI_TUNFD_H
/// The utun descriptor behind packetFlow, or -1; `ifname` (if not NULL) gets e.g. "utun5".
int maski_find_utun_fd(char *ifname, int ifname_len);
#endif

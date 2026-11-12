/* End-to-end check of the C API in callback mode (no TUN, no root):
 * maski_start -> CONNECTED -> ICMP echoes to 10.90.0.1 through maski_send_packets, replies through the
 * packets callback -> maski_network_changed (fresh socket) -> more echoes -> maski_stats -> maski_stop.
 * build: tools/ffi_smoke.sh ; run: MASKI_CONFIG='{...json...}' ./target/apple-linktest/ffi_smoke */
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "maski.h"

static atomic_int replies, connected;
static char my_addr[64];

static void on_event(void *ctx, int32_t kind, const char *json) {
    printf("event %d %s\n", kind, json);
    if (kind == MASKI_EVENT_CONNECTED) {
        const char *a = strstr(json, "\"address\":\"");
        if (a) { a += 11; size_t n = strcspn(a, "\""); memcpy(my_addr, a, n < 63 ? n : 63); }
        atomic_store(&connected, 1);
    }
}
static void on_packets(void *ctx, const uint8_t *const *p, const size_t *l, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (l[i] >= 28 && p[i][9] == 1 && p[i][20] == 0) atomic_fetch_add(&replies, 1);
}
static uint16_t csum(const uint8_t *b, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (b[i] << 8) | b[i + 1];
    if (n & 1) s += b[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return ~s;
}
static void echo(MaskiHandle *h, uint16_t seq) {
    uint8_t pk[60] = {0x45, 0, 0, 60, 0, 0, 0x40, 0, 64, 1};
    inet_pton(AF_INET, my_addr, pk + 12);
    inet_pton(AF_INET, "10.90.0.1", pk + 16);
    uint16_t c = csum(pk, 20); pk[10] = c >> 8; pk[11] = c;
    pk[20] = 8; pk[24] = 0x6d; pk[26] = seq >> 8; pk[27] = seq;
    memset(pk + 28, 0x55, 32);
    c = csum(pk + 20, 40); pk[22] = c >> 8; pk[23] = c;
    const uint8_t *pp = pk; size_t ll = sizeof pk;
    maski_send_packets(h, &pp, &ll, 1);
}
static void on_log(int32_t level, const char *line) { printf("log %s\n", line); }
int main(void) {
    if (getenv("MASKI_LOG")) maski_set_log(on_log, atoi(getenv("MASKI_LOG")));
    const char *cfg = getenv("MASKI_CONFIG");
    if (!cfg) { fprintf(stderr, "MASKI_CONFIG not set\n"); return 2; }
    MaskiHandle *h = maski_start(cfg, -1, on_packets, on_event, NULL);
    if (!h) return 1;
    for (int i = 0; i < 100 && !atomic_load(&connected); i++) usleep(50000);
    if (!atomic_load(&connected)) { maski_stop(h); return 1; }
    for (int i = 0; i < 20; i++) { echo(h, i); usleep(50000); }
    usleep(500000);
    int r1 = atomic_load(&replies);
    maski_network_changed(h, NULL);
    for (int i = 20; i < 40; i++) { echo(h, i); usleep(50000); }
    usleep(500000);
    printf("replies before network_changed %d/20, after %d/20\n", r1, atomic_load(&replies) - r1);
    /* MASKI_MIGRATIONS=N: N more network changes, 10 echoes after each; one line per move. */
    int nm = getenv("MASKI_MIGRATIONS") ? atoi(getenv("MASKI_MIGRATIONS")) : 0;
    for (int m = 0; m < nm; m++) {
        int r0 = atomic_load(&replies);
        maski_network_changed(h, NULL);
        echo(h, 90); echo(h, 91); echo(h, 92);   /* traffic racing the move */
        usleep(300000);
        r0 = atomic_load(&replies);
        for (int i = 0; i < 10; i++) { echo(h, 100 + i); usleep(100000); }
        usleep(400000);
        printf("move %d replies %d/10\n", m, atomic_load(&replies) - r0);
        fflush(stdout);
    }
    MaskiStats s;
    bool ok = maski_stats(h, &s);
    printf("stats ok=%d connected=%d gen=%llu tx=%llu rx=%llu migrations=%llu rtt=%llu us mtu=%u\n", ok, s.connected,
        s.generation, s.tx_packets, s.rx_packets, s.migrations, s.rtt_us, s.path_mtu);
    maski_stop(h);
    printf("stopped\n");
    return 0;
}

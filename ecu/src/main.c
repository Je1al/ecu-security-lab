#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uds.h"

#ifdef __linux__

#include <signal.h>
#include <time.h>

#include "server.h"
#include "socketcan.h"

static volatile int g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint32_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

int main(int argc, char **argv) {
    const char *iface = "vcan0";
    uds_mode_t mode = UDS_MODE_INSECURE;
    uint32_t rx_id = 0x7E0, tx_id = 0x7E8;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iface") && i + 1 < argc) {
            iface = argv[++i];
        } else if (!strcmp(argv[i], "--secure")) {
            mode = UDS_MODE_SECURE;
        } else if (!strcmp(argv[i], "--insecure")) {
            mode = UDS_MODE_INSECURE;
        } else if (!strcmp(argv[i], "--rx") && i + 1 < argc) {
            rx_id = (uint32_t)strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--tx") && i + 1 < argc) {
            tx_id = (uint32_t)strtoul(argv[++i], NULL, 0);
        }
    }

    transport_t tp;
    int rc = socketcan_open(&tp, iface);
    if (rc < 0) {
        fprintf(stderr, "failed to open %s (rc=%d). Is the vcan interface up?\n",
                iface, rc);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("ecu-security-lab on %s  rx=0x%03X tx=0x%03X  mode=%s\n", iface, rx_id,
           tx_id, mode == UDS_MODE_SECURE ? "secure" : "insecure");
    fflush(stdout);

    uds_server_run(&tp, rx_id, tx_id, mode, now_ms, &g_stop);
    tp.close(&tp);
    return 0;
}

#else /* the SocketCAN bus backend is Linux-only */

int main(void) {
    printf("ecu-security-lab: the SocketCAN bus backend is Linux-only.\n");
    printf("On this platform the protocol cores are covered by the unit tests "
           "(run: ctest).\n");
    printf("Run the full target plus the attacks on Linux/Docker/CI -- see "
           "README.\n");
    return 0;
}

#endif

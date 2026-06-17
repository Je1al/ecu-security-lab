#include "socketcan.h"

#ifdef __linux__

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

typedef struct {
    int fd;
} sc_ctx;

static int sc_send(transport_t *self, const can_frame_t *frame) {
    sc_ctx *c = self->ctx;
    struct can_frame cf;
    memset(&cf, 0, sizeof cf);
    cf.can_id = frame->id;
    cf.can_dlc = frame->len > CAN_MAX_DLEN ? CAN_MAX_DLEN : frame->len;
    memcpy(cf.data, frame->data, cf.can_dlc);
    ssize_t w = write(c->fd, &cf, sizeof cf);
    return (w == (ssize_t)sizeof cf) ? 0 : -1;
}

static int sc_recv(transport_t *self, can_frame_t *out) {
    sc_ctx *c = self->ctx;
    struct can_frame cf;
    ssize_t r = read(c->fd, &cf, sizeof cf);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; /* recv timeout: no frame */
        }
        return -1;
    }
    if (r < (ssize_t)sizeof cf) {
        return 0;
    }
    out->id = cf.can_id & CAN_SFF_MASK;
    out->len = cf.can_dlc > CAN_MAX_DLEN ? CAN_MAX_DLEN : cf.can_dlc;
    memcpy(out->data, cf.data, out->len);
    return 1;
}

static void sc_close(transport_t *self) {
    sc_ctx *c = self->ctx;
    if (c) {
        if (c->fd >= 0) {
            close(c->fd);
        }
        free(c);
    }
    self->ctx = NULL;
}

int socketcan_open(transport_t *t, const char *iface) {
    int fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -2;
    }

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof addr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -3;
    }

    /* 100 ms receive timeout so the server loop can service the S3 timer. */
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    sc_ctx *c = malloc(sizeof *c);
    if (!c) {
        close(fd);
        return -4;
    }
    c->fd = fd;
    t->ctx = c;
    t->send = sc_send;
    t->recv = sc_recv;
    t->close = sc_close;
    return 0;
}

#else /* non-Linux: no SocketCAN */

int socketcan_open(transport_t *t, const char *iface) {
    (void)t;
    (void)iface;
    return -100;
}

#endif

/*
 * transport.h -- CAN transport HAL.
 *
 * The ECU core (ISO-TP / UDS) talks to the bus only through this interface, so it
 * stays portable and testable. Backends implement it:
 *   - in-process: frames travel through an in-memory queue (tests, any OS)
 *   - SocketCAN : raw AF_CAN sockets on Linux vcan/can (added in M3)
 */
#ifndef ECU_TRANSPORT_H
#define ECU_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#define CAN_MAX_DLEN 8

/* A classic (non-FD) CAN 2.0 data frame. */
typedef struct {
    uint32_t id;                  /* 11-bit identifier (29-bit extended later) */
    uint8_t len;                  /* payload length, 0..CAN_MAX_DLEN */
    uint8_t data[CAN_MAX_DLEN];   /* payload bytes */
} can_frame_t;

/*
 * Transport vtable. Return codes:
 *   send:  0 on success, <0 on error.
 *   recv:  1 if a frame was read into *out, 0 if none available, <0 on error.
 */
typedef struct transport {
    void *ctx;
    int (*send)(struct transport *self, const can_frame_t *frame);
    int (*recv)(struct transport *self, can_frame_t *out);
    void (*close)(struct transport *self);
} transport_t;

#endif /* ECU_TRANSPORT_H */

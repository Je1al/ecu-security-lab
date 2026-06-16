/*
 * isotp.h -- ISO-TP (ISO 15765-2) transport layer, implemented from scratch.
 *
 * The design is event-driven: the receiver is fed one CAN frame at a time and the
 * sender is polled for one frame at a time. There is no blocking and no hidden
 * I/O, so the segmentation/reassembly logic is fully deterministic and unit-
 * testable on any OS, while the same code drives a real SocketCAN bus in the ECU
 * server loop (see uds_server).
 *
 * Scope: classic (normal) addressing, 11-bit ids, CAN 2.0 (<= 8 data bytes).
 * Supported PCI: Single Frame, First Frame, Consecutive Frame, Flow Control
 * (with block size). STmin pacing is parsed but not enforced here (it matters on
 * a real bus, not for in-memory reassembly).
 */
#ifndef ECU_ISOTP_H
#define ECU_ISOTP_H

#include <stddef.h>
#include <stdint.h>

#include "transport.h"

/* Largest payload an ISO-TP First Frame can announce (12-bit length field). */
#define ISOTP_MAX_PAYLOAD 4095u

/* PCI frame type, high nibble of byte 0. */
enum {
    ISOTP_PCI_SF = 0x0, /* Single Frame      */
    ISOTP_PCI_FF = 0x1, /* First Frame       */
    ISOTP_PCI_CF = 0x2, /* Consecutive Frame */
    ISOTP_PCI_FC = 0x3  /* Flow Control      */
};

/* Flow Control status, low nibble of byte 0 of an FC frame. */
enum {
    ISOTP_FS_CTS = 0x0,  /* Clear To Send */
    ISOTP_FS_WAIT = 0x1, /* Wait          */
    ISOTP_FS_OVFLW = 0x2 /* Overflow      */
};

typedef enum {
    ISOTP_OK_MORE = 0,      /* frame consumed; more frames expected           */
    ISOTP_OK_DONE = 1,      /* a complete message is available to the caller  */
    ISOTP_OK_SEND_FC = 2,   /* caller must transmit the produced Flow Control */
    ISOTP_ERR_PROTO = -1,   /* protocol violation (bad sequence, bad PCI)     */
    ISOTP_ERR_OVERFLOW = -2 /* message larger than the caller's buffer        */
} isotp_status_t;

/* ------------------------------------------------------------------ receiver */

typedef struct {
    int state;                      /* internal reassembly state          */
    uint8_t buf[ISOTP_MAX_PAYLOAD]; /* reassembly buffer                  */
    size_t expected;                /* total length announced by FF       */
    size_t got;                     /* bytes reassembled so far           */
    uint8_t next_sn;                /* next expected CF sequence number   */
    uint8_t fc_bs;                  /* block size we advertise (0 = all)  */
    uint8_t fc_stmin;               /* STmin we advertise                 */
    uint8_t block_count;            /* CFs received in the current block  */
} isotp_rx_t;

/* Reset a receiver to idle. Advertised flow control defaults to BS=0, STmin=0;
 * set rx->fc_bs / rx->fc_stmin afterwards to change them. */
void isotp_rx_reset(isotp_rx_t *rx);

/*
 * Feed one received CAN frame.
 *   ISOTP_OK_DONE     -> *out holds the message, *out_len its length.
 *   ISOTP_OK_SEND_FC  -> *fc_out holds a Flow Control frame (id = fc_id) that the
 *                        caller must transmit back to the sender.
 *   ISOTP_OK_MORE     -> consumed, waiting for more frames.
 *   ISOTP_ERR_*       -> error; the receiver has been reset.
 */
isotp_status_t isotp_rx_feed(isotp_rx_t *rx, const can_frame_t *f, uint8_t *out,
                             size_t cap, size_t *out_len, can_frame_t *fc_out,
                             uint32_t fc_id);

/* -------------------------------------------------------------------- sender */

typedef struct {
    int state;           /* internal segmentation state               */
    const uint8_t *data; /* message being sent (not owned)            */
    size_t len;          /* message length                            */
    size_t sent;         /* bytes emitted so far                      */
    uint8_t next_sn;     /* sequence number of the next CF            */
    uint32_t tx_id;      /* CAN id frames are emitted on              */
    int pad;             /* pad short frames to 8 bytes               */
    uint8_t pad_byte;    /* padding value                             */
    uint8_t bs;          /* block size granted by the last FC         */
    uint8_t bs_count;    /* CFs emitted in the current block          */
} isotp_tx_t;

/* Begin sending a message. With len <= 7 the first poll yields a Single Frame;
 * otherwise it yields a First Frame and the sender then waits for Flow Control. */
void isotp_tx_start(isotp_tx_t *tx, uint32_t tx_id, const uint8_t *data,
                    size_t len, int pad, uint8_t pad_byte);

/* Pull the next frame to transmit. Returns 1 (frame written to *out), 0 (nothing
 * to send right now -- finished, or waiting for Flow Control), or <0 on error. */
int isotp_tx_poll(isotp_tx_t *tx, can_frame_t *out);

/* Non-zero once the whole message has been emitted. */
int isotp_tx_done(const isotp_tx_t *tx);

/* Feed a received Flow Control frame to a sender waiting after a First Frame or a
 * completed block. */
isotp_status_t isotp_tx_on_fc(isotp_tx_t *tx, const can_frame_t *fc);

#endif /* ECU_ISOTP_H */

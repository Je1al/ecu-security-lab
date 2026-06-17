#include "server.h"

#include "isotp.h"

/* Transmit a fully segmented response, answering Flow Control as needed. */
static void send_response(transport_t *tp, uint32_t tx_id, const uint8_t *resp,
                          size_t len, clock_ms_fn now, volatile int *stop) {
    isotp_tx_t tx;
    can_frame_t out, in;
    isotp_tx_start(&tx, tx_id, resp, len, 1, 0xCC);

    while (!*stop) {
        int r = isotp_tx_poll(&tx, &out);
        if (r == 1) {
            tp->send(tp, &out);
            continue;
        }
        if (r < 0) {
            return;
        }
        /* r == 0: finished, or waiting for Flow Control. */
        if (isotp_tx_done(&tx)) {
            return;
        }
        int got = tp->recv(tp, &in);
        if (got == 1 && (in.data[0] >> 4) == ISOTP_PCI_FC) {
            if (isotp_tx_on_fc(&tx, &in) < 0) {
                return;
            }
        } else if (got < 0) {
            return;
        }
        (void)now;
    }
}

void uds_server_run(transport_t *tp, uint32_t rx_id, uint32_t tx_id,
                    uds_mode_t mode, clock_ms_fn now, volatile int *stop) {
    uds_server_t s;
    isotp_rx_t rx;
    can_frame_t f, fc;
    uint8_t req[ISOTP_MAX_PAYLOAD];
    uint8_t resp[ISOTP_MAX_PAYLOAD];
    size_t req_len = 0;

    uds_init(&s, mode);
    isotp_rx_reset(&rx);

    while (!*stop) {
        int got = tp->recv(tp, &f);
        if (got == 0) {
            uds_on_tick(&s, now()); /* idle: let S3 expire */
            continue;
        }
        if (got < 0) {
            break;
        }
        if (f.id != rx_id) {
            continue; /* not addressed to us */
        }

        isotp_status_t st = isotp_rx_feed(&rx, &f, req, sizeof req, &req_len, &fc,
                                          tx_id);
        if (st == ISOTP_OK_SEND_FC) {
            tp->send(tp, &fc);
            continue;
        }
        if (st < 0) {
            isotp_rx_reset(&rx);
            continue;
        }
        if (st != ISOTP_OK_DONE) {
            continue;
        }

        int n = uds_process(&s, now(), req, req_len, resp, sizeof resp);
        if (n > 0) {
            send_response(tp, tx_id, resp, (size_t)n, now, stop);
        }
    }
}

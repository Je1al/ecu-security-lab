#include "isotp.h"

#include <string.h>

/* Internal states. */
enum { RX_IDLE = 0, RX_WAIT_CF = 1 };
enum {
    TX_IDLE = 0,
    TX_SF,      /* ready to emit a Single Frame   */
    TX_FF,      /* ready to emit a First Frame    */
    TX_WAIT_FC, /* waiting for Flow Control        */
    TX_CF,      /* ready to emit Consecutive Frames */
    TX_DONE
};

/* Set the DLC and, if requested, pad the rest of the frame to 8 bytes. */
static void finalize(can_frame_t *f, uint8_t used, int pad, uint8_t pad_byte) {
    if (pad) {
        for (uint8_t i = used; i < CAN_MAX_DLEN; i++) {
            f->data[i] = pad_byte;
        }
        f->len = CAN_MAX_DLEN;
    } else {
        f->len = used;
    }
}

/* ----------------------------------------------------------------- receiver */

void isotp_rx_reset(isotp_rx_t *rx) {
    memset(rx, 0, sizeof(*rx));
    rx->state = RX_IDLE;
}

static void build_fc(can_frame_t *fc, uint32_t id, uint8_t fs, uint8_t bs,
                     uint8_t stmin) {
    fc->id = id;
    fc->data[0] = (uint8_t)((ISOTP_PCI_FC << 4) | (fs & 0x0F));
    fc->data[1] = bs;
    fc->data[2] = stmin;
    finalize(fc, 3, 0, 0);
}

isotp_status_t isotp_rx_feed(isotp_rx_t *rx, const can_frame_t *f, uint8_t *out,
                             size_t cap, size_t *out_len, can_frame_t *fc_out,
                             uint32_t fc_id) {
    uint8_t pci = (uint8_t)(f->data[0] >> 4);

    if (rx->state == RX_IDLE) {
        if (pci == ISOTP_PCI_SF) {
            size_t len = f->data[0] & 0x0F;
            if (len == 0 || len > 7) {
                return ISOTP_ERR_PROTO;
            }
            if (len > cap) {
                return ISOTP_ERR_OVERFLOW;
            }
            memcpy(out, &f->data[1], len);
            *out_len = len;
            return ISOTP_OK_DONE;
        }
        if (pci == ISOTP_PCI_FF) {
            size_t len = (size_t)((f->data[0] & 0x0F) << 8) | f->data[1];
            if (len < 8) { /* such a message must use a Single Frame */
                return ISOTP_ERR_PROTO;
            }
            if (len > cap || len > ISOTP_MAX_PAYLOAD) {
                /* tell the sender to abort */
                build_fc(fc_out, fc_id, ISOTP_FS_OVFLW, 0, 0);
                isotp_rx_reset(rx);
                return ISOTP_ERR_OVERFLOW;
            }
            memcpy(rx->buf, &f->data[2], 6);
            rx->expected = len;
            rx->got = 6;
            rx->next_sn = 1;
            rx->block_count = 0;
            rx->state = RX_WAIT_CF;
            build_fc(fc_out, fc_id, ISOTP_FS_CTS, rx->fc_bs, rx->fc_stmin);
            return ISOTP_OK_SEND_FC;
        }
        /* Stray CF/FC with no message in progress: ignore. */
        return ISOTP_OK_MORE;
    }

    /* RX_WAIT_CF */
    if (pci != ISOTP_PCI_CF) {
        isotp_rx_reset(rx);
        return ISOTP_ERR_PROTO;
    }
    uint8_t sn = f->data[0] & 0x0F;
    if (sn != rx->next_sn) {
        isotp_rx_reset(rx);
        return ISOTP_ERR_PROTO;
    }
    size_t remaining = rx->expected - rx->got;
    size_t n = remaining < 7 ? remaining : 7;
    memcpy(rx->buf + rx->got, &f->data[1], n);
    rx->got += n;
    rx->next_sn = (uint8_t)((rx->next_sn + 1) & 0x0F);
    rx->block_count++;

    if (rx->got >= rx->expected) {
        memcpy(out, rx->buf, rx->expected);
        *out_len = rx->expected;
        isotp_rx_reset(rx);
        return ISOTP_OK_DONE;
    }
    if (rx->fc_bs != 0 && rx->block_count >= rx->fc_bs) {
        rx->block_count = 0;
        build_fc(fc_out, fc_id, ISOTP_FS_CTS, rx->fc_bs, rx->fc_stmin);
        return ISOTP_OK_SEND_FC;
    }
    return ISOTP_OK_MORE;
}

/* ------------------------------------------------------------------- sender */

void isotp_tx_start(isotp_tx_t *tx, uint32_t tx_id, const uint8_t *data,
                    size_t len, int pad, uint8_t pad_byte) {
    memset(tx, 0, sizeof(*tx));
    tx->data = data;
    tx->len = len;
    tx->tx_id = tx_id;
    tx->pad = pad;
    tx->pad_byte = pad_byte;
    tx->next_sn = 1;
    tx->state = (len <= 7) ? TX_SF : TX_FF;
}

int isotp_tx_done(const isotp_tx_t *tx) { return tx->state == TX_DONE; }

int isotp_tx_poll(isotp_tx_t *tx, can_frame_t *out) {
    switch (tx->state) {
    case TX_SF:
        out->id = tx->tx_id;
        out->data[0] = (uint8_t)((ISOTP_PCI_SF << 4) | (tx->len & 0x0F));
        memcpy(&out->data[1], tx->data, tx->len);
        finalize(out, (uint8_t)(1 + tx->len), tx->pad, tx->pad_byte);
        tx->state = TX_DONE;
        return 1;

    case TX_FF:
        out->id = tx->tx_id;
        out->data[0] = (uint8_t)((ISOTP_PCI_FF << 4) | ((tx->len >> 8) & 0x0F));
        out->data[1] = (uint8_t)(tx->len & 0xFF);
        memcpy(&out->data[2], tx->data, 6);
        finalize(out, 8, tx->pad, tx->pad_byte);
        tx->sent = 6;
        tx->next_sn = 1;
        tx->state = TX_WAIT_FC;
        return 1;

    case TX_CF: {
        size_t remaining = tx->len - tx->sent;
        size_t n = remaining < 7 ? remaining : 7;
        out->id = tx->tx_id;
        out->data[0] = (uint8_t)((ISOTP_PCI_CF << 4) | (tx->next_sn & 0x0F));
        memcpy(&out->data[1], tx->data + tx->sent, n);
        finalize(out, (uint8_t)(1 + n), tx->pad, tx->pad_byte);
        tx->sent += n;
        tx->next_sn = (uint8_t)((tx->next_sn + 1) & 0x0F);
        tx->bs_count++;

        if (tx->sent >= tx->len) {
            tx->state = TX_DONE;
        } else if (tx->bs != 0 && tx->bs_count >= tx->bs) {
            tx->state = TX_WAIT_FC; /* block done, await the next FC */
        }
        return 1;
    }

    case TX_WAIT_FC:
    case TX_DONE:
    case TX_IDLE:
    default:
        return 0;
    }
}

isotp_status_t isotp_tx_on_fc(isotp_tx_t *tx, const can_frame_t *fc) {
    if (tx->state != TX_WAIT_FC) {
        return ISOTP_ERR_PROTO;
    }
    if ((fc->data[0] >> 4) != ISOTP_PCI_FC) {
        return ISOTP_ERR_PROTO;
    }
    uint8_t fs = fc->data[0] & 0x0F;
    switch (fs) {
    case ISOTP_FS_CTS:
        tx->bs = fc->data[1];
        tx->bs_count = 0;
        tx->state = TX_CF;
        return ISOTP_OK_MORE;
    case ISOTP_FS_WAIT:
        return ISOTP_OK_MORE; /* stay in TX_WAIT_FC */
    case ISOTP_FS_OVFLW:
        tx->state = TX_DONE;
        return ISOTP_ERR_OVERFLOW;
    default:
        return ISOTP_ERR_PROTO;
    }
}

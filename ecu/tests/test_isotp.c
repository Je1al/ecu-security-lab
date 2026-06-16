/*
 * Unit tests for the ISO-TP layer. Pure logic, no sockets -- runs on any OS.
 * The round-trip helper couples a sender and a receiver and shuttles frames
 * (including Flow Control) between them, exactly as a real bus would.
 */
#include <stdio.h>
#include <string.h>

#include "isotp.h"

static int g_fail = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("  FAIL: %s\n", (msg));                                      \
            g_fail++;                                                           \
        }                                                                       \
    } while (0)

/* Drive one full message from sender to receiver; returns 0 on a faithful
 * round trip, a negative code otherwise. */
static int roundtrip(const uint8_t *msg, size_t len, uint8_t fc_bs, int pad) {
    isotp_tx_t tx;
    isotp_rx_t rx;
    uint8_t out[ISOTP_MAX_PAYLOAD];
    size_t out_len = 0;
    can_frame_t f, fc;

    isotp_tx_start(&tx, 0x7E8, msg, len, pad, 0xCC);
    isotp_rx_reset(&rx);
    rx.fc_bs = fc_bs;

    for (int guard = 0; guard < 100000; guard++) {
        int r = isotp_tx_poll(&tx, &f);
        if (r < 0) {
            return -1;
        }
        if (r == 1) {
            isotp_status_t st =
                isotp_rx_feed(&rx, &f, out, sizeof out, &out_len, &fc, 0x7E0);
            if (st == ISOTP_OK_DONE) {
                if (out_len != len) {
                    return -2;
                }
                if (len && memcmp(out, msg, len) != 0) {
                    return -3;
                }
                return 0;
            }
            if (st == ISOTP_OK_SEND_FC) {
                if (isotp_tx_on_fc(&tx, &fc) < 0) {
                    return -4;
                }
            } else if (st < 0) {
                return -5;
            }
            continue;
        }
        /* r == 0: sender produced nothing */
        return isotp_tx_done(&tx) ? -6 : -7;
    }
    return -8;
}

static void test_roundtrips(void) {
    printf("test_roundtrips\n");
    const size_t sizes[] = {1, 6, 7, 8, 13, 64, 127, 1000, ISOTP_MAX_PAYLOAD};
    uint8_t msg[ISOTP_MAX_PAYLOAD];
    for (size_t i = 0; i < ISOTP_MAX_PAYLOAD; i++) {
        msg[i] = (uint8_t)(i * 31 + 7);
    }
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        size_t n = sizes[i];
        char m[64];
        snprintf(m, sizeof m, "roundtrip len=%zu bs=0 nopad", n);
        CHECK(roundtrip(msg, n, 0, 0) == 0, m);
        snprintf(m, sizeof m, "roundtrip len=%zu bs=4 pad", n);
        CHECK(roundtrip(msg, n, 4, 1) == 0, m);
        snprintf(m, sizeof m, "roundtrip len=%zu bs=1 pad", n);
        CHECK(roundtrip(msg, n, 1, 1) == 0, m);
    }
}

static void test_single_frame_encoding(void) {
    printf("test_single_frame_encoding\n");
    uint8_t msg[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    isotp_tx_t tx;
    can_frame_t f;
    isotp_tx_start(&tx, 0x123, msg, sizeof msg, 0, 0xCC);
    int r = isotp_tx_poll(&tx, &f);
    CHECK(r == 1, "SF produced");
    CHECK(f.id == 0x123, "SF id");
    CHECK(f.data[0] == 0x05, "SF PCI = 0x05");
    CHECK(f.len == 6, "SF dlc = 1 + len");
    CHECK(memcmp(&f.data[1], msg, 5) == 0, "SF payload");
    CHECK(isotp_tx_done(&tx), "SF leaves sender done");
}

static void test_first_frame_encoding(void) {
    printf("test_first_frame_encoding\n");
    uint8_t msg[10] = {0};
    isotp_tx_t tx;
    can_frame_t f;
    isotp_tx_start(&tx, 0x7E8, msg, sizeof msg, 0, 0xCC);
    int r = isotp_tx_poll(&tx, &f);
    CHECK(r == 1, "FF produced");
    CHECK(f.data[0] == 0x10, "FF PCI high nibble + len hi");
    CHECK(f.data[1] == 10, "FF len low byte");
    CHECK(f.len == 8, "FF dlc = 8");
    /* Without a Flow Control, the sender must not emit CFs yet. */
    CHECK(isotp_tx_poll(&tx, &f) == 0, "no CF before FC");
}

static void test_bad_sequence_number(void) {
    printf("test_bad_sequence_number\n");
    isotp_rx_t rx;
    isotp_rx_reset(&rx);
    uint8_t out[64];
    size_t out_len = 0;
    can_frame_t fc;

    can_frame_t ff = {.id = 0x7E0, .len = 8, .data = {0x10, 12, 1, 2, 3, 4, 5, 6}};
    CHECK(isotp_rx_feed(&rx, &ff, out, sizeof out, &out_len, &fc, 0x7E8) ==
              ISOTP_OK_SEND_FC,
          "FF -> send FC");
    /* Expected SN is 1; deliver SN 2 instead. */
    can_frame_t cf = {.id = 0x7E0, .len = 8, .data = {0x22, 7, 8, 9, 10, 11, 12, 0}};
    CHECK(isotp_rx_feed(&rx, &cf, out, sizeof out, &out_len, &fc, 0x7E8) ==
              ISOTP_ERR_PROTO,
          "wrong SN -> protocol error");
}

static void test_overflow(void) {
    printf("test_overflow\n");
    isotp_rx_t rx;
    isotp_rx_reset(&rx);
    uint8_t out[8]; /* tiny buffer */
    size_t out_len = 0;
    can_frame_t fc;
    /* FF announcing 100 bytes into an 8-byte buffer. */
    can_frame_t ff = {.id = 0x7E0, .len = 8, .data = {0x10, 100, 0, 0, 0, 0, 0, 0}};
    isotp_status_t st =
        isotp_rx_feed(&rx, &ff, out, sizeof out, &out_len, &fc, 0x7E8);
    CHECK(st == ISOTP_ERR_OVERFLOW, "oversized FF -> overflow");
    CHECK((fc.data[0] & 0x0F) == ISOTP_FS_OVFLW, "overflow FC status emitted");
}

int main(void) {
    test_roundtrips();
    test_single_frame_encoding();
    test_first_frame_encoding();
    test_bad_sequence_number();
    test_overflow();

    if (g_fail == 0) {
        printf("ISO-TP: all tests passed\n");
        return 0;
    }
    printf("ISO-TP: %d check(s) failed\n", g_fail);
    return 1;
}

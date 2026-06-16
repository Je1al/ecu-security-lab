/* Unit tests for the UDS core (M3 services). Pure logic, runs on any OS. */
#include <stdio.h>
#include <string.h>

#include "uds.h"

static int g_fail = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("  FAIL: %s\n", (msg));                                      \
            g_fail++;                                                           \
        }                                                                       \
    } while (0)

static void test_read_vin(void) {
    printf("test_read_vin\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t req[] = {0x22, 0xF1, 0x90};
    uint8_t resp[64];
    int n = uds_process(&s, 0, req, sizeof req, resp, sizeof resp);
    CHECK(n == 3 + 17, "VIN response length");
    CHECK(resp[0] == 0x62 && resp[1] == 0xF1 && resp[2] == 0x90, "VIN positive header");
    CHECK(memcmp(&resp[3], "WLAB1234567890123", 17) == 0, "VIN bytes");
}

static void test_unknown_did(void) {
    printf("test_unknown_did\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t req[] = {0x22, 0xAB, 0xCD};
    uint8_t resp[64];
    int n = uds_process(&s, 0, req, sizeof req, resp, sizeof resp);
    CHECK(n == 3, "neg length");
    CHECK(resp[0] == 0x7F && resp[1] == 0x22 && resp[2] == 0x31,
          "unknown DID -> requestOutOfRange");
}

static void test_tester_present(void) {
    printf("test_tester_present\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[8];
    uint8_t tp[] = {0x3E, 0x00};
    CHECK(uds_process(&s, 0, tp, sizeof tp, resp, sizeof resp) == 2, "TP responds");
    CHECK(resp[0] == 0x7E && resp[1] == 0x00, "TP positive response");
    uint8_t tp_sup[] = {0x3E, 0x80};
    CHECK(uds_process(&s, 0, tp_sup, sizeof tp_sup, resp, sizeof resp) == 0,
          "TP suppressed -> no response");
}

static void test_session_control(void) {
    printf("test_session_control\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[8];
    uint8_t ext[] = {0x10, 0x03};
    CHECK(uds_process(&s, 100, ext, sizeof ext, resp, sizeof resp) == 6,
          "DSC extended response");
    CHECK(resp[0] == 0x50 && resp[1] == 0x03, "DSC positive header");
    CHECK(s.session == UDS_SESSION_EXTENDED, "session is extended");
    uint8_t bad[] = {0x10, 0x09};
    int n = uds_process(&s, 200, bad, sizeof bad, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x12, "bad session -> subFunctionNotSupported");
}

static void test_write_did_requires_session(void) {
    printf("test_write_did_requires_session\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[16];
    uint8_t payload[16];
    for (int i = 0; i < 16; i++) {
        payload[i] = (uint8_t)(0xA0 + i);
    }

    uint8_t w[3 + 16] = {0x2E, 0x01, 0x00};
    memcpy(&w[3], payload, 16);

    /* Default session: not allowed. */
    int n = uds_process(&s, 0, w, sizeof w, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x22, "write in default -> conditionsNotCorrect");

    /* Enter extended, then write succeeds and reads back. */
    uint8_t ext[] = {0x10, 0x03};
    uds_process(&s, 10, ext, sizeof ext, resp, sizeof resp);
    n = uds_process(&s, 20, w, sizeof w, resp, sizeof resp);
    CHECK(n == 3 && resp[0] == 0x6E, "write in extended -> positive");

    uint8_t r[] = {0x22, 0x01, 0x00};
    uint8_t rresp[32];
    n = uds_process(&s, 30, r, sizeof r, rresp, sizeof rresp);
    CHECK(n == 3 + 16 && memcmp(&rresp[3], payload, 16) == 0, "config read back");
}

static void test_s3_timeout(void) {
    printf("test_s3_timeout\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[8];
    uint8_t ext[] = {0x10, 0x03};
    uds_process(&s, 1000, ext, sizeof ext, resp, sizeof resp);
    CHECK(s.session == UDS_SESSION_EXTENDED, "in extended session");
    /* Idle past S3 (5000 ms): the next request sees the default session. */
    uint8_t tp[] = {0x3E, 0x00};
    uds_process(&s, 1000 + 5001, tp, sizeof tp, resp, sizeof resp);
    CHECK(s.session == UDS_SESSION_DEFAULT, "session reverted after S3");
}

static void test_unsupported_service(void) {
    printf("test_unsupported_service\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[8];
    uint8_t req[] = {0x99, 0x00};
    int n = uds_process(&s, 0, req, sizeof req, resp, sizeof resp);
    CHECK(n == 3 && resp[0] == 0x7F && resp[2] == 0x11,
          "unknown service -> serviceNotSupported");
}

static void test_length_check(void) {
    printf("test_length_check\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[8];
    uint8_t req[] = {0x22, 0xF1}; /* too short for a DID */
    int n = uds_process(&s, 0, req, sizeof req, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x13, "short read DID -> invalidLength");
}

int main(void) {
    test_read_vin();
    test_unknown_did();
    test_tester_present();
    test_session_control();
    test_write_did_requires_session();
    test_s3_timeout();
    test_unsupported_service();
    test_length_check();

    if (g_fail == 0) {
        printf("UDS: all tests passed\n");
        return 0;
    }
    printf("UDS: %d check(s) failed\n", g_fail);
    return 1;
}

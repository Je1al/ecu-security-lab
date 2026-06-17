/*
 * Tests for SecurityAccess (0x27) and ReadMemoryByAddress (0x23): they assert the
 * deliberate weaknesses are present in the INSECURE build and fixed in the SECURE
 * build. These doubles as executable documentation of each weakness.
 */
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

#define SEC_KEY_XOR 0xA5A5A5A5u

static uint32_t request_seed(uds_server_t *s, uint32_t now) {
    uint8_t req[] = {0x27, 0x01};
    uint8_t resp[16];
    int n = uds_process(s, now, req, sizeof req, resp, sizeof resp);
    if (n != 6) {
        return 0;
    }
    return ((uint32_t)resp[2] << 24) | ((uint32_t)resp[3] << 16) |
           ((uint32_t)resp[4] << 8) | resp[5];
}

static int send_key(uds_server_t *s, uint32_t now, uint32_t key, uint8_t *resp,
                    size_t cap) {
    uint8_t req[6] = {0x27, 0x02, (uint8_t)(key >> 24), (uint8_t)(key >> 16),
                      (uint8_t)(key >> 8), (uint8_t)key};
    return uds_process(s, now, req, sizeof req, resp, cap);
}

/* #1 predictable seed: consecutive seeds increment by one. */
static void test_predictable_seed(void) {
    printf("test_predictable_seed\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint32_t a = request_seed(&s, 0);
    /* re-request before unlocking: seed advances predictably */
    s.seed_requested = 0; /* allow a fresh seed */
    uint32_t b = request_seed(&s, 1);
    CHECK(b == a + 1, "seed increments predictably");
}

/* #2 reversible seed->key: key = seed XOR constant unlocks. */
static void test_reversible_key(void) {
    printf("test_reversible_key\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint32_t seed = request_seed(&s, 0);
    uint8_t resp[8];
    int n = send_key(&s, 1, seed ^ SEC_KEY_XOR, resp, sizeof resp);
    CHECK(n == 2 && resp[0] == 0x67 && resp[1] == 0x02, "derived key unlocks");
    CHECK(s.unlocked == 1, "server is unlocked");
}

/* #3 no lockout: many wrong keys, always invalidKey, never a delay. */
static void test_no_lockout_insecure(void) {
    printf("test_no_lockout_insecure\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    request_seed(&s, 0);
    uint8_t resp[8];
    for (int i = 0; i < 50; i++) {
        int n = send_key(&s, 2, (uint32_t)(0xDEAD0000u + i), resp, sizeof resp);
        CHECK(n == 3 && resp[2] == 0x35, "wrong key -> invalidKey, no lockout");
    }
}

/* #4 auth bypass: requesting a seed (no key) is enough to read memory; the
 * secret is recoverable. */
static void test_read_memory_bypass(void) {
    printf("test_read_memory_bypass\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    request_seed(&s, 0); /* no key sent -> still 'locked' */
    CHECK(s.unlocked == 0, "not actually unlocked");

    /* read 32 bytes at the secret offset 0xC0 */
    uint8_t req[] = {0x23, 0x11, 0xC0, 0x20};
    uint8_t resp[64];
    int n = uds_process(&s, 1, req, sizeof req, resp, sizeof resp);
    CHECK(n == 1 + 0x20 && resp[0] == 0x63, "memory read without a valid key");
    CHECK(memcmp(&resp[1], "FLAG{ecu_secret_unlocked}", 25) == 0,
          "secret recovered via bypass");
}

/* #5 NRC oracle: a locked reader distinguishes valid-but-protected (0x33) from
 * out-of-range (0x31). */
static void test_nrc_oracle_insecure(void) {
    printf("test_nrc_oracle_insecure\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_INSECURE);
    uint8_t resp[16];

    uint8_t in_range[] = {0x23, 0x11, 0x10, 0x04}; /* addr 0x10, size 4 */
    int n = uds_process(&s, 0, in_range, sizeof in_range, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x33, "valid+protected -> securityAccessDenied");

    uint8_t oor[] = {0x23, 0x11, 0xFE, 0x10}; /* runs past 256 */
    n = uds_process(&s, 0, oor, sizeof oor, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x31, "out-of-range -> requestOutOfRange");
}

/* Secure build: lockout after repeated wrong keys. */
static void test_secure_lockout(void) {
    printf("test_secure_lockout\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_SECURE);
    request_seed(&s, 0);
    uint8_t resp[8];
    int n;
    n = send_key(&s, 1, 0x11111111u, resp, sizeof resp);
    CHECK(resp[2] == 0x35, "1st wrong -> invalidKey");
    n = send_key(&s, 2, 0x22222222u, resp, sizeof resp);
    CHECK(resp[2] == 0x35, "2nd wrong -> invalidKey");
    n = send_key(&s, 3, 0x33333333u, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x36, "3rd wrong -> exceedNumberOfAttempts");
    /* now locked out: even a fresh seed+key is refused until the delay passes */
    request_seed(&s, 4);
    n = send_key(&s, 5, 0x44444444u, resp, sizeof resp);
    CHECK(resp[2] == 0x37, "locked -> requiredTimeDelayNotExpired");
}

/* Secure build: ReadMemory needs a real unlock and gives a uniform NRC. */
static void test_secure_read_memory(void) {
    printf("test_secure_read_memory\n");
    uds_server_t s;
    uds_init(&s, UDS_MODE_SECURE);
    request_seed(&s, 0); /* seed only: the bypass must NOT work here */
    uint8_t req[] = {0x23, 0x11, 0xC0, 0x10};
    uint8_t resp[64];
    int n = uds_process(&s, 1, req, sizeof req, resp, sizeof resp);
    CHECK(n == 3 && resp[2] == 0x31, "secure: no bypass, uniform requestOutOfRange");

    /* properly unlock, then the read succeeds */
    uint32_t seed = s.last_seed;
    send_key(&s, 2, seed ^ SEC_KEY_XOR, resp, sizeof resp);
    CHECK(s.unlocked == 1, "secure: valid key unlocks");
    n = uds_process(&s, 3, req, sizeof req, resp, sizeof resp);
    CHECK(n == 1 + 0x10 && resp[0] == 0x63, "secure: read after unlock");
}

int main(void) {
    test_predictable_seed();
    test_reversible_key();
    test_no_lockout_insecure();
    test_read_memory_bypass();
    test_nrc_oracle_insecure();
    test_secure_lockout();
    test_secure_read_memory();

    if (g_fail == 0) {
        printf("SecurityAccess/ReadMemory: all tests passed\n");
        return 0;
    }
    printf("SecurityAccess/ReadMemory: %d check(s) failed\n", g_fail);
    return 1;
}

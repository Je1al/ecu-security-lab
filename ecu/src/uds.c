#include "uds.h"

#include <string.h>

/* The secret the attacker is meant to recover by chaining the SecurityAccess and
 * ReadMemoryByAddress weaknesses (M4). It lives inside the pseudo-firmware. */
static const char SECRET[] = "FLAG{ecu_secret_unlocked}";
#define SECRET_OFFSET 0xC0u

/* SecurityAccess parameters. The seed->key relation is intentionally a trivial,
 * reversible XOR (see VULNERABILITIES.md, weakness #2). */
#define SEC_KEY_XOR 0xA5A5A5A5u
#define SEC_MAX_ATTEMPTS 3
#define SEC_LOCKOUT_MS 10000u

void uds_init(uds_server_t *s, uds_mode_t mode) {
    memset(s, 0, sizeof(*s));
    s->mode = mode;
    s->session = UDS_SESSION_DEFAULT;
    s->s3_ms = 5000;
    s->last_activity_ms = 0;

    memcpy(s->vin, "WLAB1234567890123", 17);

    for (unsigned i = 0; i < UDS_MEM_SIZE; i++) {
        s->memory[i] = (uint8_t)i;
    }
    memcpy(&s->memory[SECRET_OFFSET], SECRET, sizeof(SECRET) - 1);
}

void uds_on_tick(uds_server_t *s, uint32_t now_ms) {
    if (s->session != UDS_SESSION_DEFAULT &&
        (now_ms - s->last_activity_ms) > s->s3_ms) {
        s->session = UDS_SESSION_DEFAULT;
        s->unlocked = 0;
        s->seed_requested = 0;
    }
}

static int neg(uint8_t *resp, size_t cap, uint8_t sid, uint8_t nrc) {
    if (cap < 3) {
        return -1;
    }
    resp[0] = UDS_NEG_RESPONSE;
    resp[1] = sid;
    resp[2] = nrc;
    return 3;
}

/* 0x10 DiagnosticSessionControl */
static int svc_dsc(uds_server_t *s, const uint8_t *req, size_t req_len,
                   uint8_t *resp, size_t cap) {
    if (req_len != 2) {
        return neg(resp, cap, UDS_SID_DSC, UDS_NRC_INVALID_LENGTH);
    }
    uint8_t sub = req[1];
    int suppress = sub & UDS_SUPPRESS_POS_RSP_BIT;
    uint8_t sess = sub & 0x7F;
    if (sess != UDS_SESSION_DEFAULT && sess != UDS_SESSION_PROGRAMMING &&
        sess != UDS_SESSION_EXTENDED) {
        return neg(resp, cap, UDS_SID_DSC, UDS_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    s->session = sess;
    if (sess == UDS_SESSION_DEFAULT) {
        s->unlocked = 0; /* leaving an elevated session drops privileges */
    }
    if (suppress) {
        return 0;
    }
    if (cap < 6) {
        return -1;
    }
    resp[0] = UDS_SID_DSC + UDS_POS_RESPONSE_BIT;
    resp[1] = sess;
    resp[2] = 0x00; /* P2_server_max  = 0x0032 = 50 ms   */
    resp[3] = 0x32;
    resp[4] = 0x01; /* P2*_server_max = 0x01F4 * 10 ms    */
    resp[5] = 0xF4;
    return 6;
}

/* 0x3E TesterPresent */
static int svc_tester_present(const uint8_t *req, size_t req_len, uint8_t *resp,
                              size_t cap) {
    if (req_len != 2) {
        return neg(resp, cap, UDS_SID_TESTER_PRESENT, UDS_NRC_INVALID_LENGTH);
    }
    uint8_t sub = req[1];
    int suppress = sub & UDS_SUPPRESS_POS_RSP_BIT;
    if ((sub & 0x7F) != 0x00) {
        return neg(resp, cap, UDS_SID_TESTER_PRESENT,
                   UDS_NRC_SUBFUNC_NOT_SUPPORTED);
    }
    if (suppress) {
        return 0;
    }
    if (cap < 2) {
        return -1;
    }
    resp[0] = UDS_SID_TESTER_PRESENT + UDS_POS_RESPONSE_BIT;
    resp[1] = 0x00;
    return 2;
}

/* 0x22 ReadDataByIdentifier */
static int svc_read_did(uds_server_t *s, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t cap) {
    if (req_len != 3) {
        return neg(resp, cap, UDS_SID_READ_DID, UDS_NRC_INVALID_LENGTH);
    }
    uint16_t did = (uint16_t)((req[1] << 8) | req[2]);
    const uint8_t *data;
    size_t n;
    switch (did) {
    case 0xF190: /* VIN */
        data = s->vin;
        n = sizeof(s->vin);
        break;
    case 0xF187: /* spare part number */
        data = (const uint8_t *)"ECU-LAB-0001";
        n = 12;
        break;
    case 0x0100: /* writable config block */
        data = s->cfg;
        n = sizeof(s->cfg);
        break;
    default:
        return neg(resp, cap, UDS_SID_READ_DID, UDS_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (cap < 3 + n) {
        return -1;
    }
    resp[0] = UDS_SID_READ_DID + UDS_POS_RESPONSE_BIT;
    resp[1] = req[1];
    resp[2] = req[2];
    memcpy(&resp[3], data, n);
    return (int)(3 + n);
}

/* 0x2E WriteDataByIdentifier */
static int svc_write_did(uds_server_t *s, const uint8_t *req, size_t req_len,
                         uint8_t *resp, size_t cap) {
    if (req_len < 3) {
        return neg(resp, cap, UDS_SID_WRITE_DID, UDS_NRC_INVALID_LENGTH);
    }
    uint16_t did = (uint16_t)((req[1] << 8) | req[2]);
    size_t n = req_len - 3;
    switch (did) {
    case 0x0100:
        if (s->session == UDS_SESSION_DEFAULT) {
            return neg(resp, cap, UDS_SID_WRITE_DID,
                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        }
        if (n != sizeof(s->cfg)) {
            return neg(resp, cap, UDS_SID_WRITE_DID, UDS_NRC_INVALID_LENGTH);
        }
        memcpy(s->cfg, &req[3], sizeof(s->cfg));
        break;
    default: /* VIN / spare part number / unknown are not writable */
        return neg(resp, cap, UDS_SID_WRITE_DID, UDS_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (cap < 3) {
        return -1;
    }
    resp[0] = UDS_SID_WRITE_DID + UDS_POS_RESPONSE_BIT;
    resp[1] = req[1];
    resp[2] = req[2];
    return 3;
}

/* 0x27 SecurityAccess (level 1: 0x01 requestSeed / 0x02 sendKey).
 *
 * Deliberate weaknesses in the INSECURE build:
 *   #1 the seed is a tiny incrementing counter -> predictable
 *   #2 expected key = seed XOR constant -> reversible
 *   #3 wrong keys are neither counted nor rate-limited -> brute forceable
 * The SECURE build keeps the same wire format but counts attempts and enforces a
 * lockout after SEC_MAX_ATTEMPTS.
 */
static int svc_security_access(uds_server_t *s, uint32_t now_ms,
                               const uint8_t *req, size_t req_len, uint8_t *resp,
                               size_t cap) {
    if (req_len < 2) {
        return neg(resp, cap, UDS_SID_SECURITY_ACCESS, UDS_NRC_INVALID_LENGTH);
    }
    uint8_t sub = req[1];
    int suppress = sub & UDS_SUPPRESS_POS_RSP_BIT;
    uint8_t level = sub & 0x7F;

    if (level == 0x01) { /* requestSeed */
        if (req_len != 2) {
            return neg(resp, cap, UDS_SID_SECURITY_ACCESS,
                       UDS_NRC_INVALID_LENGTH);
        }
        uint32_t seed;
        if (s->unlocked) {
            seed = 0; /* ISO 14229: already unlocked -> zero seed */
        } else {
            /* weakness #1: predictable, low-entropy seed */
            s->last_seed = 0xA5A50000u + s->sec_counter;
            s->sec_counter++;
            s->seed_requested = 1;
            seed = s->last_seed;
        }
        if (suppress) {
            return 0;
        }
        if (cap < 6) {
            return -1;
        }
        resp[0] = UDS_SID_SECURITY_ACCESS + UDS_POS_RESPONSE_BIT;
        resp[1] = 0x01;
        resp[2] = (uint8_t)(seed >> 24);
        resp[3] = (uint8_t)(seed >> 16);
        resp[4] = (uint8_t)(seed >> 8);
        resp[5] = (uint8_t)(seed);
        return 6;
    }

    if (level == 0x02) { /* sendKey */
        if (req_len != 6) {
            return neg(resp, cap, UDS_SID_SECURITY_ACCESS,
                       UDS_NRC_INVALID_LENGTH);
        }
        if (s->mode == UDS_MODE_SECURE && now_ms < s->lockout_until_ms) {
            return neg(resp, cap, UDS_SID_SECURITY_ACCESS,
                       UDS_NRC_TIME_DELAY_NOT_EXPIRED);
        }
        if (!s->seed_requested) {
            return neg(resp, cap, UDS_SID_SECURITY_ACCESS,
                       UDS_NRC_CONDITIONS_NOT_CORRECT);
        }
        uint32_t key = ((uint32_t)req[2] << 24) | ((uint32_t)req[3] << 16) |
                       ((uint32_t)req[4] << 8) | (uint32_t)req[5];
        uint32_t expected = s->last_seed ^ SEC_KEY_XOR; /* weakness #2 */

        if (key == expected) {
            s->unlocked = 1;
            s->seed_requested = 0;
            s->sec_attempts = 0;
            if (suppress) {
                return 0;
            }
            if (cap < 2) {
                return -1;
            }
            resp[0] = UDS_SID_SECURITY_ACCESS + UDS_POS_RESPONSE_BIT;
            resp[1] = 0x02;
            return 2;
        }

        /* wrong key */
        if (s->mode == UDS_MODE_SECURE) {
            s->sec_attempts++;
            if (s->sec_attempts >= SEC_MAX_ATTEMPTS) {
                s->lockout_until_ms = now_ms + SEC_LOCKOUT_MS;
                s->sec_attempts = 0;
                s->seed_requested = 0;
                return neg(resp, cap, UDS_SID_SECURITY_ACCESS,
                           UDS_NRC_EXCEED_ATTEMPTS);
            }
            return neg(resp, cap, UDS_SID_SECURITY_ACCESS, UDS_NRC_INVALID_KEY);
        }
        /* weakness #3: insecure build never counts or delays */
        return neg(resp, cap, UDS_SID_SECURITY_ACCESS, UDS_NRC_INVALID_KEY);
    }

    return neg(resp, cap, UDS_SID_SECURITY_ACCESS, UDS_NRC_SUBFUNC_NOT_SUPPORTED);
}

/* 0x23 ReadMemoryByAddress.
 *
 * Deliberate weaknesses in the INSECURE build:
 *   #4 the authorization gate checks seed_requested instead of unlocked, so
 *      merely *requesting* a seed (no valid key) is enough to read memory.
 *   #5 a locked reader gets securityAccessDenied (0x33) for valid-but-protected
 *      addresses and requestOutOfRange (0x31) past the end -> an oracle that maps
 *      the memory layout. The SECURE build returns a uniform 0x31.
 */
static int svc_read_memory(uds_server_t *s, const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t cap) {
    if (req_len < 2) {
        return neg(resp, cap, UDS_SID_READ_MEMORY, UDS_NRC_INVALID_LENGTH);
    }
    uint8_t alfid = req[1];
    uint8_t addr_len = alfid & 0x0F;
    uint8_t size_len = (uint8_t)((alfid >> 4) & 0x0F);
    if (addr_len < 1 || addr_len > 2 || size_len < 1 || size_len > 2) {
        return neg(resp, cap, UDS_SID_READ_MEMORY, UDS_NRC_REQUEST_OUT_OF_RANGE);
    }
    if (req_len != (size_t)(2 + addr_len + size_len)) {
        return neg(resp, cap, UDS_SID_READ_MEMORY, UDS_NRC_INVALID_LENGTH);
    }

    uint32_t addr = 0, size = 0;
    size_t p = 2;
    for (uint8_t i = 0; i < addr_len; i++) {
        addr = (addr << 8) | req[p++];
    }
    for (uint8_t i = 0; i < size_len; i++) {
        size = (size << 8) | req[p++];
    }
    if (size == 0 || addr + size > UDS_MEM_SIZE) {
        return neg(resp, cap, UDS_SID_READ_MEMORY, UDS_NRC_REQUEST_OUT_OF_RANGE);
    }

    int authorized = s->unlocked ||
                     (s->mode == UDS_MODE_INSECURE && s->seed_requested); /* #4 */
    if (!authorized) {
        if (s->mode == UDS_MODE_INSECURE) {
            return neg(resp, cap, UDS_SID_READ_MEMORY,
                       UDS_NRC_SECURITY_ACCESS_DENIED); /* #5 oracle */
        }
        return neg(resp, cap, UDS_SID_READ_MEMORY, UDS_NRC_REQUEST_OUT_OF_RANGE);
    }

    if (cap < 1 + size) {
        return -1;
    }
    resp[0] = UDS_SID_READ_MEMORY + UDS_POS_RESPONSE_BIT;
    memcpy(&resp[1], &s->memory[addr], size);
    return (int)(1 + size);
}

int uds_process(uds_server_t *s, uint32_t now_ms, const uint8_t *req,
                size_t req_len, uint8_t *resp, size_t cap) {
    uds_on_tick(s, now_ms);
    if (req_len == 0) {
        return 0; /* nothing to act on */
    }
    s->last_activity_ms = now_ms;

    uint8_t sid = req[0];
    switch (sid) {
    case UDS_SID_DSC:
        return svc_dsc(s, req, req_len, resp, cap);
    case UDS_SID_TESTER_PRESENT:
        return svc_tester_present(req, req_len, resp, cap);
    case UDS_SID_READ_DID:
        return svc_read_did(s, req, req_len, resp, cap);
    case UDS_SID_WRITE_DID:
        return svc_write_did(s, req, req_len, resp, cap);
    case UDS_SID_SECURITY_ACCESS:
        return svc_security_access(s, now_ms, req, req_len, resp, cap);
    case UDS_SID_READ_MEMORY:
        return svc_read_memory(s, req, req_len, resp, cap);
    default:
        return neg(resp, cap, sid, UDS_NRC_SERVICE_NOT_SUPPORTED);
    }
}

/*
 * uds.h -- UDS (ISO 14229) server core.
 *
 * Pure request/response logic: feed one complete UDS request (already reassembled
 * by the ISO-TP layer) and get back one complete response. No sockets, no timers
 * of its own -- the caller supplies a millisecond clock so the S3 session timeout
 * is testable. The same core runs behind ISO-TP on a real vcan/can bus.
 *
 * Two build modes select between the deliberately vulnerable behaviour and a
 * hardened comparison (see uds_mode_t); the differences land with SecurityAccess
 * in M4.
 */
#ifndef ECU_UDS_H
#define ECU_UDS_H

#include <stddef.h>
#include <stdint.h>

/* Service identifiers. */
enum {
    UDS_SID_DSC = 0x10,             /* DiagnosticSessionControl   */
    UDS_SID_READ_MEMORY = 0x23,     /* ReadMemoryByAddress  (M4)  */
    UDS_SID_SECURITY_ACCESS = 0x27, /* SecurityAccess       (M4)  */
    UDS_SID_TESTER_PRESENT = 0x3E,  /* TesterPresent              */
    UDS_SID_READ_DID = 0x22,        /* ReadDataByIdentifier       */
    UDS_SID_WRITE_DID = 0x2E        /* WriteDataByIdentifier      */
};

/* Negative response codes (ISO 14229). */
enum {
    UDS_NRC_GENERAL_REJECT = 0x10,
    UDS_NRC_SERVICE_NOT_SUPPORTED = 0x11,
    UDS_NRC_SUBFUNC_NOT_SUPPORTED = 0x12,
    UDS_NRC_INVALID_LENGTH = 0x13,
    UDS_NRC_CONDITIONS_NOT_CORRECT = 0x22,
    UDS_NRC_REQUEST_OUT_OF_RANGE = 0x31,
    UDS_NRC_SECURITY_ACCESS_DENIED = 0x33,
    UDS_NRC_INVALID_KEY = 0x35,
    UDS_NRC_EXCEED_ATTEMPTS = 0x36,
    UDS_NRC_TIME_DELAY_NOT_EXPIRED = 0x37,
    UDS_NRC_SUBFUNC_NOT_SUPPORTED_IN_SESSION = 0x7E,
    UDS_NRC_SERVICE_NOT_SUPPORTED_IN_SESSION = 0x7F
};

/* Diagnostic sessions. */
enum {
    UDS_SESSION_DEFAULT = 0x01,
    UDS_SESSION_PROGRAMMING = 0x02,
    UDS_SESSION_EXTENDED = 0x03
};

#define UDS_NEG_RESPONSE 0x7F
#define UDS_POS_RESPONSE_BIT 0x40
#define UDS_SUPPRESS_POS_RSP_BIT 0x80

/* Size of the pseudo-firmware/memory region exposed via ReadMemoryByAddress. */
#define UDS_MEM_SIZE 256u

typedef enum {
    UDS_MODE_INSECURE = 0, /* deliberate vulnerabilities enabled */
    UDS_MODE_SECURE = 1     /* hardened comparison build          */
} uds_mode_t;

typedef struct uds_server {
    uds_mode_t mode;
    uint8_t session;
    uint32_t s3_ms;            /* session timeout (default 5000 ms) */
    uint32_t last_activity_ms; /* time of the last accepted request */

    /* Data identifiers. */
    uint8_t vin[17]; /* DID 0xF190, read-only        */
    uint8_t cfg[16]; /* DID 0x0100, writable config  */

    /* SecurityAccess state (M4). */
    int unlocked;             /* 1 once a valid key was supplied   */
    uint32_t last_seed;       /* seed handed out for subfunc 0x01  */
    uint16_t sec_counter;     /* drives the (predictable) seed     */
    int seed_requested;       /* a seed is outstanding             */
    uint8_t sec_attempts;     /* consecutive failed key attempts   */
    uint32_t lockout_until_ms;/* delay window after too many fails */

    /* Pseudo-firmware exposed via ReadMemoryByAddress (M4). */
    uint8_t memory[UDS_MEM_SIZE];
} uds_server_t;

void uds_init(uds_server_t *s, uds_mode_t mode);

/* Advance the clock; reverts to the default session (and re-locks security) after
 * S3 milliseconds of inactivity. Called automatically by uds_process. */
void uds_on_tick(uds_server_t *s, uint32_t now_ms);

/*
 * Process one complete UDS request. Returns the response length written to
 * `resp` (> 0), 0 when the positive response is suppressed, or < 0 when `cap`
 * is too small to hold the response.
 */
int uds_process(uds_server_t *s, uint32_t now_ms, const uint8_t *req,
                size_t req_len, uint8_t *resp, size_t cap);

#endif /* ECU_UDS_H */

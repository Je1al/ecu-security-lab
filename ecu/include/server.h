/*
 * server.h -- the UDS-over-ISO-TP server loop.
 *
 * Portable: it only depends on the transport HAL, ISO-TP and UDS cores, plus a
 * caller-supplied millisecond clock. The Linux SocketCAN backend (and the `ecu`
 * binary) wire a real bus into it; the unit tests exercise the cores directly.
 */
#ifndef ECU_SERVER_H
#define ECU_SERVER_H

#include <stdint.h>

#include "transport.h"
#include "uds.h"

typedef uint32_t (*clock_ms_fn)(void);

/* Serve requests on rx_id and answer on tx_id until *stop becomes non-zero. */
void uds_server_run(transport_t *tp, uint32_t rx_id, uint32_t tx_id,
                    uds_mode_t mode, clock_ms_fn now, volatile int *stop);

#endif /* ECU_SERVER_H */

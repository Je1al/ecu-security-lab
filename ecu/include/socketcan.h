/*
 * socketcan.h -- Linux SocketCAN backend for the transport HAL.
 *
 * Binds a raw AF_CAN socket to `iface` (e.g. "vcan0" or a real "can0"). Linux
 * only; on other platforms socketcan_open returns -100 so the rest of the build
 * still compiles.
 */
#ifndef ECU_SOCKETCAN_H
#define ECU_SOCKETCAN_H

#include "transport.h"

/* Returns 0 on success, negative on error. */
int socketcan_open(transport_t *t, const char *iface);

#endif /* ECU_SOCKETCAN_H */

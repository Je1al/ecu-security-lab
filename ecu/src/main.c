#include <stdio.h>

#include "transport.h"

/*
 * M1 skeleton entry point. The UDS / ISO-TP state machine and the SocketCAN
 * backend land in later milestones; this confirms the build is wired up and the
 * transport HAL header compiles.
 */
int main(void) {
    can_frame_t frame = {.id = 0x7E0, .len = 0};
    printf("ecu-security-lab target -- skeleton (M1).\n");
    printf("transport HAL ready; default request id = 0x%03X.\n", frame.id);
    return 0;
}

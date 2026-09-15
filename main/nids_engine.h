#pragma once

#include "nids_types.h"

// Create the queue and its only consumer before enabling sniffer capture.
void nids_engine_start(void);
// Wi-Fi task callback: copies one packet, never waits; full queues drop packets.
void nids_engine_submit(const nids_pkt_info_t *packet);

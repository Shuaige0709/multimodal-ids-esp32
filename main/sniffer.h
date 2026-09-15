#pragma once

#include "nids_types.h"

// Called in the Wi-Fi driver task: the sink must copy the packet without waiting.
typedef void (*sniffer_packet_sink_t)(const nids_pkt_info_t *packet);
// Wi-Fi and the packet consumer must already be initialized.
void sniffer_start(sniffer_packet_sink_t sink);

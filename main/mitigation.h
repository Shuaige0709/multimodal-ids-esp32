#pragma once

#include "nids_types.h"

// Single caller: the analysis task.
void mitigation_on_attack(const nids_pkt_info_t *info);
uint32_t mitigation_event_count(void);

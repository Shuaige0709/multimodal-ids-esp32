#pragma once
#include "nids_m3.h"

#ifndef NIDS_BEACON_ALERT_ENABLE
#define NIDS_BEACON_ALERT_ENABLE 1
#endif

static inline uint8_t nids_alert_policy_apply(uint8_t sources)
{
#if !NIDS_BEACON_ALERT_ENABLE
    sources = (uint8_t)(sources & (uint8_t)~NIDS_M3_BEACON);
#endif
    return sources;
}

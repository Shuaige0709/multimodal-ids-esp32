#ifndef NIDS_M3_H
#define NIDS_M3_H

#include <stdbool.h>
#include <stdint.h>

#include "m3_model.h"

#define NIDS_M3_HISTORY 16

enum {
    NIDS_M3_RF = 1,
    NIDS_M3_BEACON = 2,
    NIDS_M3_ARP = 4,
};

typedef struct {
    uint64_t uptime_ms;
    nids_m3_features_t features;
    uint32_t probe_packets;
    uint32_t beacon_packets;
    uint32_t deauth_targeted;
    uint32_t twin_bssid;
    uint32_t gw_flip;
    uint32_t reconnects;
    bool gw_mac_valid;
    uint8_t gw_mac[6];
} nids_m3_input_t;

typedef struct {
    uint64_t times[NIDS_M3_HISTORY];
    uint8_t votes[NIDS_M3_HISTORY];
    uint8_t targets[NIDS_M3_HISTORY];
    uint8_t last_five_twin;
    uint8_t last_five_probe;
    uint8_t last_five_beacon;
    uint8_t history_count;
    uint8_t last_five_count;
    uint8_t baseline_mac[6];
    uint32_t previous_flip;
    uint32_t previous_reconnects;
    uint64_t previous_time_ms;
    bool have_baseline;
    bool have_previous;
} nids_m3_state_t;

typedef struct {
    int raw_vote;
    uint8_t sources;
} nids_m3_result_t;

void nids_m3_reset(nids_m3_state_t *state);
nids_m3_result_t nids_m3_step(nids_m3_state_t *state, const nids_m3_input_t *input);

#endif

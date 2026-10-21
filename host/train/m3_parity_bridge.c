/* Host-only ABI for checking the exact firmware M3 state machine from Python. */
#include <string.h>

#include "nids_m3.h"

static nids_m3_state_t state;

void m3_parity_reset(void)
{
    nids_m3_reset(&state);
}

unsigned m3_parity_step(uint64_t uptime_ms, float total, float density,
                        float beacon, float targeted, float auth,
                        float bssid, float twin, uint32_t probe_count,
                        uint32_t beacon_count, uint32_t targeted_count,
                        uint32_t twin_count, uint32_t flip, uint32_t reconnects,
                        const uint8_t *mac, int mac_valid)
{
    nids_m3_input_t input = {0};
    input.uptime_ms = uptime_ms;
    input.features = (nids_m3_features_t){total, density, beacon, targeted,
                                          auth, bssid, twin};
    input.probe_packets = probe_count;
    input.beacon_packets = beacon_count;
    input.deauth_targeted = targeted_count;
    input.twin_bssid = twin_count;
    input.gw_flip = flip;
    input.reconnects = reconnects;
    input.gw_mac_valid = mac_valid != 0;
    if (mac_valid) memcpy(input.gw_mac, mac, 6);
    nids_m3_result_t result = nids_m3_step(&state, &input);
    return (unsigned)(result.sources | ((unsigned)result.raw_vote << 8));
}

unsigned m3_parity_state_bytes(void)
{
    return sizeof(state);
}

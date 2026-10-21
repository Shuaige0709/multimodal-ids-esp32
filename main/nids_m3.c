#include "nids_m3.h"

#include <string.h>

static unsigned count_last_five(uint8_t bits, uint8_t count)
{
    unsigned sum = 0;
    for (uint8_t i = 0; i < count; i++) {
        sum += (bits >> i) & 1U;
    }
    return sum;
}

void nids_m3_reset(nids_m3_state_t *state)
{
    memset(state, 0, sizeof(*state));
}

nids_m3_result_t nids_m3_step(nids_m3_state_t *state, const nids_m3_input_t *input)
{
    if (state->have_previous && input->uptime_ms < state->previous_time_ms) {
        nids_m3_reset(state);
    }
    nids_m3_result_t result = {0};
    result.raw_vote = nids_m3_predict(&input->features);

    if (state->history_count == NIDS_M3_HISTORY) {
        memmove(state->times, state->times + 1,
                (NIDS_M3_HISTORY - 1) * sizeof(state->times[0]));
        memmove(state->votes, state->votes + 1, NIDS_M3_HISTORY - 1);
        memmove(state->targets, state->targets + 1, NIDS_M3_HISTORY - 1);
        state->history_count--;
    }
    uint8_t last = state->history_count++;
    state->times[last] = input->uptime_ms;
    state->votes[last] = result.raw_vote != 0;
    state->targets[last] = input->deauth_targeted > 0;

    unsigned recent_votes = 0;
    unsigned recent_targets = 0;
    for (uint8_t i = 0; i < state->history_count; i++) {
        uint64_t age = input->uptime_ms - state->times[i];
        if (age < 700) recent_votes += state->votes[i];
        if (age < 1000) recent_targets += state->targets[i];
    }

    state->last_five_twin = (uint8_t)((state->last_five_twin << 1) |
                                      (input->twin_bssid > 0));
    state->last_five_probe = (uint8_t)((state->last_five_probe << 1) |
                                       (input->probe_packets >= 16));
    state->last_five_beacon = (uint8_t)((state->last_five_beacon << 1) |
                                        (input->beacon_packets >= 6));
    if (state->last_five_count < 5) state->last_five_count++;

    bool stable = recent_votes >= 4;
    bool supported = recent_targets >= 3 ||
                     count_last_five(state->last_five_twin, state->last_five_count) >= 3 ||
                     count_last_five(state->last_five_probe, state->last_five_count) >= 3;
    if (stable && supported) result.sources |= NIDS_M3_RF;
    if (count_last_five(state->last_five_beacon, state->last_five_count) >= 3) {
        result.sources |= NIDS_M3_BEACON;
    }

    if (state->have_previous &&
        (input->gw_flip < state->previous_flip ||
         input->reconnects > state->previous_reconnects)) {
        state->have_baseline = false;
    }
    if (input->gw_mac_valid) {
        if (!state->have_baseline) {
            memcpy(state->baseline_mac, input->gw_mac, 6);
            state->have_baseline = true;
        } else if (state->have_previous && input->gw_flip > state->previous_flip &&
                   memcmp(state->baseline_mac, input->gw_mac, 6) != 0) {
            result.sources |= NIDS_M3_ARP;
        }
    }
    state->previous_flip = input->gw_flip;
    state->previous_reconnects = input->reconnects;
    state->previous_time_ms = input->uptime_ms;
    state->have_previous = true;
    return result;
}

#pragma once

#include <stdint.h>

typedef struct {
    uint32_t timestamp;
    uint32_t ipat;
    int8_t rssi;
    int8_t snr;
    uint8_t rate;
    uint16_t seq_ctrl;
    uint8_t mcs;
    uint32_t len;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint8_t bssid[6];
    uint8_t deauth_targeted;
    uint8_t seq_jump;
    uint8_t ssid_ours;
    char type_str[8];
    char subtype[16];
} nids_pkt_info_t;

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t timestamp;      // packet timestamp
    uint32_t ipat;           // inter-packet arrival time in microseconds
    int8_t rssi;             // signal strength in dBm
    int8_t snr;              // signal-to-noise ratio in dB
    uint8_t rate;            // PHY rate encoding
    uint16_t seq_ctrl;       // sequence control field from 802.11 header
    uint8_t mcs;             // modulation coding scheme for HT/VHT packets
    uint32_t len;            // packet length
    uint8_t src_mac[6];      // source MAC address (addr2)
    uint8_t dst_mac[6];      // destination MAC address (addr1)
    uint8_t bssid[6];        // addr3 (BSSID on mgmt/data)
    uint8_t deauth_targeted; // 1 if DEAUTH/DISASSOC to us or broadcast
    uint8_t seq_jump;        // 1 if sequence number jumped vs previous frame
    uint8_t ssid_ours;       // beacon/probe_resp SSID IE equals associated AP SSID
    char type_str[8];        // packet type (MGMT, CTRL, DATA, MISC)
    char subtype[16];        // detailed subtype (e.g., BEACON, PROBE_REQ)
} nids_pkt_info_t;

typedef struct {
    uint32_t queue_peak;
    bool attack_detected;
    int raw_prediction;
} nids_report_state_t;

// Telemetry window values; separate from the generated model input structure.
typedef struct {
    uint32_t pkts;
    double dens;
    uint32_t deauth;
    uint32_t probe;
    uint32_t beacon;
    uint32_t auth;
    uint32_t bssid;
    uint32_t twin;
    uint32_t rogue;
    uint32_t mgmt;
    uint32_t data;
    uint32_t ctrl;
    uint32_t bytes;
    uint32_t len_mean;
    uint32_t len_max;
    uint32_t mgmt_bytes;
    uint32_t data_bytes;
} nids_window_report_t;

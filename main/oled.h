// SSD1306 128x64 status display for the on-device NIDS demo.
#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    OLED_STATE_READY = 0,
    OLED_STATE_ALERT,
    OLED_STATE_RECOVER,
    OLED_STATE_LINK_DOWN,
} oled_state_t;

typedef enum {
    OLED_ATTACK_ANOMALY = 0,
    OLED_ATTACK_DEAUTH,
    OLED_ATTACK_AUTH,
    OLED_ATTACK_TWIN,
} oled_attack_kind_t;

typedef struct {
    oled_state_t state;
    oled_attack_kind_t attack_kind;
    bool wifi_connected;
    bool collector_ready;
    bool calib_armed;
    uint8_t channel;
    int8_t rssi;
    int raw_pred;
    int gated_pred;
    uint32_t win_packets;
    uint32_t win_deauth;
    uint32_t win_targeted;
    uint32_t win_auth;
    uint32_t win_twin;
    uint32_t reconnects;
    uint32_t backlog;
    uint32_t uart_drops;
    uint32_t hold_seconds;
} oled_status_t;

bool oled_init(void);
void oled_deinit(void);
void oled_clear(void);
void oled_show_status(const oled_status_t *status);

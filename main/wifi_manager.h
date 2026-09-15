#pragma once

#include <stdbool.h>
#include <stdint.h>

void wifi_manager_init(void);
bool wifi_manager_is_connected(void);
bool wifi_manager_take_connected_event(void);
uint32_t wifi_manager_reconnect_count(void);
const uint8_t *wifi_manager_sta_mac(void);
const char *wifi_manager_sta_mac_str(void);
const uint8_t *wifi_manager_ap_bssid(void);
const char *wifi_manager_ap_bssid_str(void);
const char *wifi_manager_ap_ssid(void);
uint8_t wifi_manager_ap_ssid_len(void);
uint8_t wifi_manager_ap_channel(void);

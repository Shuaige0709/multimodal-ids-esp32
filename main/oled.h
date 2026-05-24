// Simple SSD1306 helper (minimal features for status display)
#pragma once
#include <stdint.h>
#include <stdbool.h>

bool oled_init(void);
void oled_deinit(void);
void oled_clear(void);
void oled_show_stats(bool wifi_connected, uint32_t pkt_count, uint32_t send_interval, uint32_t free_heap,
                     int8_t rssi, uint32_t ipat, uint32_t stack_watermark, uint8_t channel,
                     uint32_t wifi_reconnect_count, uint32_t queue_depth, bool attack_flag);

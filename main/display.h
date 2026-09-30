#pragma once

#include <stdbool.h>
#include <stdint.h>

void display_prepare_bus(void);
void display_note_rssi(int8_t rssi);
void display_note_window(int raw_pred, int gated_pred, bool attack,
                         uint32_t packets, uint32_t deauth, uint32_t targeted,
                         uint32_t auth, uint32_t twin, uint32_t rogue);
void display_tick(bool wifi_up, bool collector_ready, uint8_t channel,
                  uint32_t reconnects, uint32_t backlog, uint32_t uart_drops);

#pragma once

#include <stdbool.h>
#include <stdint.h>

void display_init(void);
// Single caller: the analysis task, every 100 processed packets.
void display_update(uint32_t packets, uint32_t send_interval, uint32_t heap, int8_t rssi, uint32_t ipat,
                    uint32_t stack_remaining, uint32_t queue_depth, bool attack);

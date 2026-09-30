#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

void sniffer_prepare(void);
QueueHandle_t sniffer_queue(void);
uint32_t sniffer_drop_count(void);
void sniffer_start(void);

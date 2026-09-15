#pragma once

#include <stddef.h>
#include "nids_types.h"
#include "app_config.h"

// Start once after Wi-Fi initialization. Poll/send/encode/getters have one owner:
// the analysis task. The discovery task only publishes collector addresses.
void syslog_client_start(void);
void syslog_client_on_packet(void);
void syslog_client_poll(void);
void syslog_client_send(const char *message);
void syslog_client_log_status(uint32_t packets);
uint32_t syslog_client_interval(void);
uint32_t syslog_client_failures(void);
uint32_t syslog_client_backlog(void);

void syslog_encode(char *buf, size_t size, const nids_pkt_info_t *info, const nids_report_state_t *state,
                   uint32_t heap, int64_t uptime_ms, const nids_window_report_t *window);

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lwip/sockets.h"
#include "nids_types.h"

void syslog_client_prepare(void);
void syslog_client_start_discovery(void);
void syslog_client_on_link_up(void);

bool syslog_client_resolve(struct sockaddr_in *dest);
bool syslog_client_send(int sock, struct sockaddr_in *dest, const char *message);
void syslog_client_push(const char *message);
void syslog_client_flush(int sock, struct sockaddr_in *dest);
void syslog_client_mirror(const char *message);
void syslog_client_write_serial(const char *message);

uint32_t syslog_client_interval(void);
uint32_t syslog_client_backlog(void);
uint32_t syslog_client_dropped(void);
uint32_t syslog_client_failures(void);
uint32_t syslog_client_successes(void);
uint32_t syslog_client_uart_drops(void);
bool syslog_client_collector_known(void);

void syslog_encode(char *buf, size_t size, const nids_pkt_info_t *info, uint32_t heap,
                   int64_t uptime_ms, uint32_t queue_peak, int attack, int raw_pred,
                   uint32_t win_pkts, double win_density,
                   uint32_t win_deauth, uint32_t win_probe,
                   uint32_t win_beacon, uint32_t win_auth,
                   uint32_t win_deauth_tgt, uint32_t win_seq_jump,
                   uint32_t win_bssid, uint32_t win_twin, uint32_t win_rogue,
                   uint32_t win_mgmt, uint32_t win_data, uint32_t win_ctrl,
                   uint32_t win_bytes, uint32_t win_len_mean, uint32_t win_len_max,
                   uint32_t win_mgmt_bytes, uint32_t win_data_bytes);

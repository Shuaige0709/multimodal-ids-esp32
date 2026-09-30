#pragma once

/* Runtime policy for the on-device NIDS path.
 * Kept here so the split modules share one set of knobs.
 * This is not the refactor branch's raw-capture profile. */

#define SYSLOG_PRI 14
#define HOSTNAME "esp32-node"
#define APP_NAME "NIDS_PROBE"
#define PEN "45917"
#define SYSlOG_MODE 1
#define CHANNEL_HOP_MODE 0
#define DATASET_PROFILE 1

#define SYSLOG_MSG_MAX 864
#define SYSLOG_BACKLOG_CAP 16

#define UART_WINDOW_MIRROR_ENABLE 1
#define UART_WINDOW_MIRROR_USE_CONSOLE 1
#define UART_WINDOW_MIRROR_QUEUE_DEPTH 8

#define WIFI_RECONNECT_INITIAL_MS 500U
#define WIFI_RECONNECT_MAX_MS 4000U

#define SEQ_JUMP_THRESH 64

#define NIDS_UART_PORT UART_NUM_1
#define NIDS_UART_TX_PIN 17
#define NIDS_UART_RX_PIN 16
#define NIDS_UART_BAUD 115200

#define SNIFFER_QUEUE_LENGTH 100

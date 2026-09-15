#pragma once

// Application policy; network credentials and ports remain in net_config.h.
#define SYSLOG_PRI 14
#define HOSTNAME "esp32-node"
#define APP_NAME "NIDS_PROBE"
#define PEN "45917"
#define SYSLOG_MODE 1 // 0: console, 1: UDP, 2: UART1
#define CHANNEL_HOP_MODE 0
#define DATASET_PROFILE 1
#define SNIFFER_FIXED_CHANNEL 11
#define SNIFFER_QUEUE_LENGTH 100
#define SEQ_JUMP_THRESH 64
// Internal DRAM budget: 200 * 640 = 128000 bytes.
#define SYSLOG_BACKLOG_MAX (DATASET_PROFILE ? 200U : 128U)
#define SYSLOG_MSG_MAX 640U
#define NIDS_UART_PORT UART_NUM_1
#define NIDS_UART_TX_PIN 17
#define NIDS_UART_RX_PIN 16
#define NIDS_UART_BAUD 115200

#pragma once

// 1: raw dataset over the board's USB bridge (UART0); 0: legacy on-device NIDS.
// Capture mode preserves STA + HTTP, but does not run inference/mitigation/syslog.
#ifndef RAW_CAPTURE_ENABLED
#define RAW_CAPTURE_ENABLED 1
#endif
#define RAW_CAPTURE_BAUD 921600
#define RAW_CAPTURE_SNAPLEN 4095U // ESP32 rx_ctrl.sig_len is 12 bits; no intentional truncation.
#define RAW_CAPTURE_POOL_SLOTS 16U
#define RAW_CAPTURE_STATUS_MS 100U
#define RAW_CAPTURE_STATUS_QUEUE 8U
#define RAW_CAPTURE_HELLO_MS 2000U

// Application policy; network credentials and ports remain in net_config.h.
#define SYSLOG_PRI 14
#define HOSTNAME "esp32-node"
#define APP_NAME "NIDS_PROBE"
#define PEN "45917"
#define SYSLOG_MODE 0 // 0: console, 1: UDP, 2: UART1
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

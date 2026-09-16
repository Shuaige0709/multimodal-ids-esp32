#pragma once

#include <stddef.h>
#include <stdint.h>

// Wire integers are little endian, independent of SDK bitfield layout.
// This version is built for the little-endian original ESP32 only.
#define RAW_WIRE_VERSION 1U
#define RAW_KIND_HELLO 1U
#define RAW_KIND_PACKET 2U
#define RAW_KIND_STATUS 3U
#define RAW_FLAG_UNAVAILABLE 1U
#define RAW_FLAG_TRUNCATED 2U

typedef struct __attribute__((packed)) {
    uint8_t magic[4];
    uint8_t version;
    uint8_t kind;
    uint16_t flags;
    uint32_t body_len;
    uint64_t boot_id;
    uint32_t stream_seq;
    uint64_t device_us;
} raw_wire_header_t;

typedef struct __attribute__((packed)) {
    uint32_t packet_seq;
    uint32_t rx_timestamp_us32;
    uint16_t original_len;
    uint16_t captured_len;
    int8_t rssi;
    int8_t noise_floor;
    uint8_t pkt_type, channel, secondary_channel, rate, sig_mode, mcs, cwb;
    uint8_t smoothing, not_sounding, aggregation, stbc, fec_coding, sgi;
    uint8_t ampdu_cnt, ant, rx_state;
    uint16_t rx_ctrl_len;
    // Followed by rx_ctrl_len SDK metadata bytes, then captured_len frame bytes.
} raw_packet_meta_t;

typedef struct __attribute__((packed)) {
    uint32_t sample_seq;
    uint32_t free_heap, min_free_heap, largest_free_internal, free_internal;
    uint32_t reconnect_count, callback_count, enqueued_count, drop_pool_count;
    uint32_t invalid_count, payload_unavailable_count, truncated_count;
    uint32_t tx_fail_count, status_drop_count, packets_sent;
    uint16_t queue_depth, queue_peak, pool_free;
    uint8_t connected, primary_channel;
} raw_status_t;

_Static_assert(sizeof(raw_wire_header_t) == 32, "wire header size");
_Static_assert(sizeof(raw_packet_meta_t) == 32, "packet metadata size");
_Static_assert(sizeof(raw_status_t) == 68, "status size");

uint32_t raw_crc32(const uint8_t *data, size_t len);
// Returns encoded length, or zero when capacity is insufficient. No delimiters.
size_t raw_cobs_encode(const uint8_t *src, size_t len, uint8_t *dst, size_t capacity);

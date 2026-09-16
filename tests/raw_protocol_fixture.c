// Native-host test of the ACTUAL firmware encoder and packed wire layouts.
#include "raw_capture_protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
static uint8_t raw[4352], encoded[4400];

static void emit(uint8_t kind, uint32_t seq, uint64_t us, size_t body_len)
{
    raw_wire_header_t h = {
        .magic = {'N', 'I', 'D', 'R'}, .version = 1, .kind = kind,
        .body_len = (uint32_t)body_len, .boot_id = UINT64_C(0xf123456789abcdef),
        .stream_seq = seq, .device_us = us,
    };
    memcpy(raw, &h, sizeof(h));
    size_t len = sizeof(h) + body_len;
    uint32_t crc = raw_crc32(raw, len);
    memcpy(raw + len, &crc, sizeof(crc));
    size_t n = raw_cobs_encode(raw, len + 4, encoded, sizeof(encoded));
    assert(n != 0);
    putchar(0);
    assert(fwrite(encoded, 1, n, stdout) == n);
    putchar(0);
}

static void selftest(void)
{
    assert(raw_crc32((const uint8_t *)"123456789", 9) == UINT32_C(0xcbf43926));
    uint8_t decoded[4352];
    for (unsigned pattern = 0; pattern < 3; ++pattern) {
        for (size_t len = 0; len <= sizeof(raw); ++len) {
            for (size_t i = 0; i < len; ++i) raw[i] = pattern == 0 ? 0 : pattern == 1 ? 0xff : (uint8_t)i;
            size_t capacity = len + len / 254 + 1;
            memset(encoded, 0xaa, sizeof(encoded));
            assert(raw_cobs_encode(raw, len, encoded, capacity - 1) == 0);
            size_t n = raw_cobs_encode(raw, len, encoded, capacity);
            assert(n > 0 && n <= capacity && encoded[capacity] == 0xaa);
            size_t in = 0, out = 0;
            while (in < n) {
                uint8_t code = encoded[in++];
                assert(code != 0 && in + code - 1 <= n);
                for (unsigned j = 1; j < code; ++j) decoded[out++] = encoded[in++];
                if (code != 255 && in < n) decoded[out++] = 0;
            }
            assert(out == len && memcmp(decoded, raw, len) == 0);
        }
    }
}

int main(void)
{
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    selftest();
    const char hello[] = "{\"target\":\"esp32\",\"snaplen\":4095}";
    memcpy(raw + sizeof(raw_wire_header_t), hello, sizeof(hello) - 1);
    emit(RAW_KIND_HELLO, 0, 99900, sizeof(hello) - 1);
    raw_status_t status = {
        .sample_seq = 7, .free_heap = 81234, .min_free_heap = 71000,
        .largest_free_internal = 32000, .free_internal = 80000,
        .reconnect_count = 2, .callback_count = 100, .enqueued_count = 95,
        .drop_pool_count = 5, .payload_unavailable_count = 3, .packets_sent = 80,
        .queue_depth = 14, .queue_peak = 16, .pool_free = 1,
        .connected = 1, .primary_channel = 3,
    };
    memcpy(raw + sizeof(raw_wire_header_t), &status, sizeof(status));
    emit(RAW_KIND_STATUS, 1, 100000, sizeof(status));
    raw_packet_meta_t packet = {
        .packet_seq = 98, .rx_timestamp_us32 = UINT32_C(0xfffffff0),
        .original_len = 4095, .captured_len = 4095, .rssi = -57, .noise_floor = -96,
        .pkt_type = 2, .channel = 3, .secondary_channel = 1, .rate = 11,
        .sig_mode = 1, .mcs = 7, .cwb = 1, .smoothing = 1, .not_sounding = 1,
        .aggregation = 1, .stbc = 2, .fec_coding = 1, .sgi = 1, .ampdu_cnt = 9,
        .ant = 1, .rx_state = 0, .rx_ctrl_len = 28,
    };
    uint8_t *body = raw + sizeof(raw_wire_header_t);
    memcpy(body, &packet, sizeof(packet));
    memset(body + sizeof(packet), 0xa5, 28);
    for (size_t i = 0; i < 4095; ++i) body[sizeof(packet) + 28 + i] = (uint8_t)i;
    emit(RAW_KIND_PACKET, 2, 101234, sizeof(packet) + 28 + 4095);
    return 0;
}

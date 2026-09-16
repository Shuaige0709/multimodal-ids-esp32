#include "raw_capture_protocol.h"

uint32_t raw_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

size_t raw_cobs_encode(const uint8_t *src, size_t len, uint8_t *dst, size_t capacity)
{
    // Conservative bound includes a final code byte at a 254-byte boundary.
    if (capacity < len + len / 254U + 1U) {
        return 0;
    }
    size_t out = 1, code_pos = 0;
    uint8_t code = 1;
    for (size_t i = 0; i < len; ++i) {
        if (src[i] == 0) {
            dst[code_pos] = code;
            code_pos = out++;
            code = 1;
        } else {
            dst[out++] = src[i];
            if (++code == 0xFF) {
                dst[code_pos] = code;
                code_pos = out++;
                code = 1;
            }
        }
    }
    dst[code_pos] = code;
    return out;
}

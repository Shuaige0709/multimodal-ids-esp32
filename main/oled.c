// SSD1306 OLED driver - Direct I2C + text rendering
#include "oled.h"
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "OLED";

#define I2C_MASTER_NUM I2C_NUM_0
#define I2C_MASTER_SDA_IO 21
#define I2C_MASTER_SCL_IO 22
#define I2C_MASTER_FREQ_HZ 400000
#define SSD1306_ADDR 0x3C
#define OLED_I2C_TIMEOUT_MS 60

static uint8_t fb[128 * 64 / 8];  // Framebuffer: 8 pages × 128 bytes

// Simple 5x8 monospace font for ASCII characters
// Each character is 5 pixels wide, 8 pixels tall
static const uint8_t simple_font[256][5] = {
    // Digits 0-9
    [0x30] = {0x7E, 0x81, 0x81, 0x81, 0x7E},  // '0'
    [0x31] = {0x00, 0x82, 0xFF, 0x80, 0x00},  // '1'
    [0x32] = {0xE2, 0x91, 0x89, 0x85, 0x83},  // '2'
    [0x33] = {0x42, 0x81, 0x89, 0x89, 0x76},  // '3'
    [0x34] = {0x1C, 0x14, 0x12, 0xFF, 0x10},  // '4'
    [0x35] = {0x47, 0x85, 0x85, 0x85, 0x79},  // '5'
    [0x36] = {0x7C, 0x8A, 0x89, 0x89, 0x72},  // '6'
    [0x37] = {0x01, 0xC1, 0x31, 0x0D, 0x03},  // '7'
    [0x38] = {0x76, 0x89, 0x89, 0x89, 0x76},  // '8'
    [0x39] = {0x4E, 0x89, 0x89, 0x8A, 0x7C},  // '9'
    
    // Letters R, I, H, S, C
    [0x52] = {0xFF, 0x09, 0x19, 0x29, 0x46},  // 'R'
    [0x49] = {0x81, 0xFF, 0x81, 0x00, 0x00},  // 'I'
    [0x48] = {0xFF, 0x08, 0x08, 0x08, 0xFF},  // 'H'
    [0x53] = {0x43, 0x85, 0x89, 0x89, 0x71},  // 'S'
    [0x43] = {0x7E, 0x81, 0x81, 0x81, 0x42},  // 'C'
    
    // Colon ':'
    [0x3A] = {0x00, 0x24, 0x00, 0x24, 0x00},  // ':'
    
    // Space
    [0x20] = {0x00, 0x00, 0x00, 0x00, 0x00},  // ' '
    
    // Minus '-'
    [0x2D] = {0x08, 0x08, 0x08, 0x08, 0x08},  // '-'
    
    // Letters 'd', 'B', 'm', 's', 'p', 'K', 'P', 'T'
    [0x64] = {0x7C, 0x82, 0x82, 0x82, 0xFC},  // 'd'
    [0x42] = {0xFF, 0x89, 0x89, 0x89, 0x76},  // 'B'
    [0x6D] = {0xFC, 0x04, 0x04, 0x04, 0xF8},  // 'm'
    [0x73] = {0x64, 0x8A, 0x8A, 0x8A, 0x34},  // 's'
    [0x70] = {0xFF, 0x12, 0x12, 0x12, 0x0C},  // 'p'
    [0x4B] = {0xFF, 0x18, 0x24, 0x42, 0x81},  // 'K'
    [0x50] = {0xFF, 0x09, 0x09, 0x09, 0x06},  // 'P'
    [0x54] = {0x01, 0x01, 0xFF, 0x01, 0x01},  // 'T'
};

static esp_err_t i2c_write_cmd(const uint8_t *data, size_t len) {
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SSD1306_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0x00, true);  // Control byte: command
    i2c_master_write(cmd, data, len, true);
    i2c_master_stop(cmd);
    esp_err_t ret = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(OLED_I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

static esp_err_t i2c_write_data(const uint8_t *data, size_t len) {
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SSD1306_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0x40, true);  // Control byte: data
    i2c_master_write(cmd, data, len, true);
    i2c_master_stop(cmd);
    esp_err_t ret = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(OLED_I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

bool oled_init(void) {
    // I2C driver should be already initialized by main.c
    // Just initialize SSD1306
    
    // SSD1306 initialization sequence
    const uint8_t init_seq[] = {
        0xAE,       // Display OFF
        0xD5, 0x80, // Clock div
        0xA8, 0x3F, // Multiplex ratio
        0xD3, 0x00, // Display offset
        0x40,       // Display start line
        0x8D, 0x14, // Charge pump enable
        0x20, 0x02, // Memory mode: page
        0xA1,       // Segment remap
        0xC8,       // COM scan direction
        0xDA, 0x12, // COM pins config
        0x81, 0xCF, // Contrast
        0xD9, 0xF1, // Pre-charge period
        0xDB, 0x40, // VCOMH
        0xA4,       // Entire display ON
        0xA6,       // Normal display (not inverted)
        0xAF        // Display ON
    };
    if (i2c_write_cmd(init_seq, sizeof(init_seq)) != ESP_OK) {
        ESP_LOGE(TAG, "SSD1306 init failed");
        return false;
    }
    
    memset(fb, 0, sizeof(fb));
    oled_clear();
    ESP_LOGI(TAG, "OLED initialized OK");
    return true;
}

void oled_deinit(void) {
    i2c_driver_delete(I2C_MASTER_NUM);
}

void oled_clear(void) {
    memset(fb, 0, sizeof(fb));
    // Send frame
    for (int page = 0; page < 8; page++) {
        uint8_t page_cmds[] = {0xB0 | page, 0x00, 0x10};
        i2c_write_cmd(page_cmds, 3);
        i2c_write_data(&fb[page * 128], 128);
    }
}

// Draw text at page and x position
static void draw_text_at(int page, int x, const char *text) {
    int pos = x;
    for (const char *p = text; *p && pos < 128 - 5; p++) {
        uint8_t c = (uint8_t)*p;
        for (int col = 0; col < 5; col++) {
            if (pos + col < 128) {
                fb[page * 128 + pos + col] = simple_font[c][col];
            }
        }
        pos += 6;  // 5 pixels + 1 space
    }
}

void oled_show_stats(bool wifi_connected, uint32_t pkt_count, uint32_t send_interval, 
                     uint32_t free_heap, int8_t rssi, uint32_t ipat, 
                     uint32_t stack_watermark, uint8_t channel, bool attack_flag) {
    memset(fb, 0, sizeof(fb));
    
    // Line 0: Status
    if (attack_flag) {
        draw_text_at(0, 0, "[ATTACK!]");
    } else {
        draw_text_at(0, 0, wifi_connected ? "WiFi" : "NoWiFi");
    }
    
    // Line 1: RSSI
    char line1[32];
    snprintf(line1, sizeof(line1), "R:%d", rssi);
    draw_text_at(1, 0, line1);
    
    // Line 2: IPAT (interval ms)
    char line2[32];
    snprintf(line2, sizeof(line2), "I:%lu", ipat / 1000);
    draw_text_at(2, 0, line2);
    
    // Line 3: HEAP (KB)
    char line3[32];
    snprintf(line3, sizeof(line3), "H:%lu", free_heap / 1024);
    draw_text_at(3, 0, line3);
    
    // Line 4: STACK
    char line4[32];
    snprintf(line4, sizeof(line4), "S:%lu", stack_watermark);
    draw_text_at(4, 0, line4);
    
    // Line 5: CHANNEL + PKT
    char line5[32];
    snprintf(line5, sizeof(line5), "C:%u P:%lu", channel, pkt_count);
    draw_text_at(5, 0, line5);
    
    // Send frame to display
    for (int page = 0; page < 8; page++) {
        uint8_t page_cmds[] = {0xB0 | page, 0x00, 0x10};
        i2c_write_cmd(page_cmds, 3);
        i2c_write_data(&fb[page * 128], 128);
    }
}



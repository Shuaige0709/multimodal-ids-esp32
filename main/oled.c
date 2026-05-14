// SSD1306 OLED driver - 8×8 font version
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

// 8×8 monospace font bitmap (8 bytes per character, column-wise)
// 8×8 monospace font bitmap (8 bytes per character, row-wise)
// Each byte represents one row, MSB=leftmost pixel
static const uint8_t font_8x8[256][8] = {
    [0x20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // space
    [0x2D] = {0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00},  // '-'
    [0x30] = {0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C},  // '0'
    [0x31] = {0x0C, 0x1C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3F},  // '1'
    [0x32] = {0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E},  // '2'
    [0x33] = {0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x66, 0x3C},  // '3'
    [0x34] = {0x0C, 0x1C, 0x3C, 0x6C, 0x7E, 0x0C, 0x0C, 0x0C},  // '4'
    [0x35] = {0x7E, 0x60, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C},  // '5'
    [0x36] = {0x3C, 0x66, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x3C},  // '6'
    [0x37] = {0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x30},  // '7'
    [0x38] = {0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x66, 0x3C},  // '8'
    [0x39] = {0x3C, 0x66, 0x66, 0x3E, 0x06, 0x06, 0x66, 0x3C},  // '9'
    [0x3A] = {0x00, 0x18, 0x18, 0x00, 0x00, 0x18, 0x18, 0x00},  // ':'
    [0x43] = {0x3E, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x3E},  // 'C'
    [0x48] = {0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x66},  // 'H'
    [0x49] = {0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C},  // 'I'
    [0x50] = {0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x60},  // 'P'
    [0x52] = {0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x66},  // 'R'
    [0x53] = {0x3E, 0x60, 0x60, 0x3C, 0x06, 0x06, 0x66, 0x3C},  // 'S'
};

static bool i2c_initialized = false;

static esp_err_t i2c_write_cmd(const uint8_t *data, size_t len)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SSD1306_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0x00, true);  // Command mode
    i2c_master_write(cmd, (uint8_t *)data, len, true);
    i2c_master_stop(cmd);

    esp_err_t ret = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(OLED_I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

static esp_err_t i2c_write_data(const uint8_t *data, size_t len)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SSD1306_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, 0x40, true);  // Data mode
    i2c_master_write(cmd, (uint8_t *)data, len, true);
    i2c_master_stop(cmd);

    esp_err_t ret = i2c_master_cmd_begin(I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(OLED_I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

bool oled_init(void)
{
    if (i2c_initialized) {
        ESP_LOGW(TAG, "I2C already initialized");
        return true;
    }

    // SSD1306 initialization sequence
    const uint8_t init_seq[] = {
        0xAE,           // Display OFF
        0xD5, 0x80,     // Clock div ratio
        0xA8, 0x3F,     // Multiplex ratio (63)
        0xD3, 0x00,     // Display offset
        0x40,           // Start line
        0x8D, 0x14,     // Charge pump enable
        0xA1,           // Segment remap
        0xC8,           // COM scan direction
        0xDA, 0x12,     // COM pins
        0x81, 0xCF,     // Contrast
        0xD9, 0xF1,     // Precharge
        0xDB, 0x40,     // VCOMH
        0xA4,           // Normal display
        0xA6,           // Not inverted
        0xAF,           // Display ON
    };

    if (i2c_write_cmd(init_seq, sizeof(init_seq)) != ESP_OK) {
        ESP_LOGE(TAG, "OLED initialization failed");
        return false;
    }

    oled_clear();
    i2c_initialized = true;
    ESP_LOGI(TAG, "OLED initialized OK");
    return true;
}

void oled_deinit(void)
{
    const uint8_t cmd = 0xAE;  // Display OFF
    i2c_write_cmd(&cmd, 1);
    i2c_initialized = false;
}

void oled_clear(void)
{
    memset(fb, 0, sizeof(fb));

    for (int page = 0; page < 8; page++) {
        const uint8_t page_cmds[] = {0xB0 | page, 0x00, 0x10};
        i2c_write_cmd(page_cmds, sizeof(page_cmds));
        i2c_write_data(&fb[page * 128], 128);
    }
}

// Draw 8×8 character into one 8-pixel-tall SSD1306 page cell.
// The font bitmap is row-wise, so each row is transposed into the page framebuffer.
static void draw_char_8x8(int page, int x_col, char ch)
{
    if (page >= 8 || x_col >= 128 - 8) return;

    const uint8_t *bitmap = font_8x8[(uint8_t)ch];

    for (int row = 0; row < 8; row++) {
        uint8_t row_bits = bitmap[row];
        for (int col = 0; col < 8; col++) {
            if (row_bits & (1u << (7 - col))) {
                fb[page * 128 + x_col + col] |= (1u << row);
            }
        }
    }
}

// Draw text horizontally starting at position (page, x_col)
// Each 8×8 character takes 8 pixels width
static void draw_text_at(int page, int x_col, const char *text)
{
    if (!text) return;

    int x_pos = x_col;
    for (int i = 0; text[i] && x_pos < 128; i++) {
        draw_char_8x8(page, x_pos, text[i]);
        x_pos += 8;  // 8 pixels per character
    }
}

void oled_show_stats(bool wifi_connected, uint32_t pkt_count, uint32_t send_interval,
                     uint32_t free_heap, int8_t rssi, uint32_t ipat,
                     uint32_t stack_watermark, uint8_t channel, bool attack_flag)
{
    static uint32_t last_update = 0;
    uint32_t now = xTaskGetTickCount();

    // Throttle updates: 1.5s minimum + every 200 packets
    if (now - last_update < pdMS_TO_TICKS(1500)) {
        return;
    }

    // Skip if heap too low (prevent crashes)
    if (free_heap < 48 * 1024) {
        return;
    }

    last_update = now;
    memset(fb, 0, sizeof(fb));  // Clear framebuffer

    // Line 0: Status (WiFi/NoWiFi/[ATTACK!])
    char status_str[20];
    if (attack_flag) {
        snprintf(status_str, sizeof(status_str), "[ATTACK!]");
    } else if (wifi_connected) {
        snprintf(status_str, sizeof(status_str), "WiFi");
    } else {
        snprintf(status_str, sizeof(status_str), "NoWiFi");
    }
    draw_text_at(0, 0, status_str);

    // Line 1: R:RSSI (left) | I:IPAT (right)
    char line1_left[20];
    snprintf(line1_left, sizeof(line1_left), "R:%d", rssi);
    draw_text_at(2, 0, line1_left);

    char line1_right[20];
    snprintf(line1_right, sizeof(line1_right), "I:%lu", ipat);
    draw_text_at(2, 64, line1_right);

    // Line 2: H:HEAP (left) | S:STACK (right)
    char line2_left[20];
    snprintf(line2_left, sizeof(line2_left), "H:%lu", free_heap / 1024);
    draw_text_at(4, 0, line2_left);

    char line2_right[20];
    snprintf(line2_right, sizeof(line2_right), "S:%lu", stack_watermark);
    draw_text_at(4, 64, line2_right);

    // Line 3: C:CH (left) | P:PKT (right)
    char line3_left[20];
    snprintf(line3_left, sizeof(line3_left), "C:%u", channel);
    draw_text_at(6, 0, line3_left);

    char line3_right[20];
    snprintf(line3_right, sizeof(line3_right), "P:%lu", pkt_count / 1000);  // Display in thousands
    draw_text_at(6, 64, line3_right);

    // Send framebuffer to display; clear skipped pages to preserve spacing
    for (int page = 0; page < 8; page++) {
        const uint8_t page_cmds[] = {0xB0 | page, 0x00, 0x10};
        if (i2c_write_cmd(page_cmds, sizeof(page_cmds)) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set page %d", page);
            continue;
        }
        const uint8_t *page_data = &fb[page * 128];
        if ((page & 1) != 0) {
            static const uint8_t blank_page[128] = {0};
            page_data = blank_page;
        }
        if (i2c_write_data(page_data, 128) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to write page %d data", page);
        }
    }
}

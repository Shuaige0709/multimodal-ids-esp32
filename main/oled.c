// SSD1306 128x64 NIDS status display.
#include "oled.h"

#include <stdio.h>
#include <string.h>

#include "driver/i2c.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

static const char *TAG = "OLED";

#define I2C_MASTER_NUM I2C_NUM_0
#define SSD1306_ADDR 0x3C
#define OLED_WIDTH 128
#define OLED_HEIGHT 64
#define OLED_I2C_TIMEOUT_MS 60

static uint8_t fb[OLED_WIDTH * OLED_HEIGHT / 8];
static bool oled_ready = false;
static bool transfer_error_logged = false;

/* Uppercase bitmap glyphs. Demo screens use scale 2 (10x14 pixels) or
 * scale 3 (15x21 pixels); no small diagnostic text is shown. */
static const uint8_t font_5x7[59][7] = {
    ['!' - ' '] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04},
    ['%' - ' '] = {0x19, 0x1A, 0x04, 0x08, 0x0B, 0x13, 0x00},
    ['-' - ' '] = {0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00},
    ['.' - ' '] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C},
    ['/' - ' '] = {0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10},
    ['0' - ' '] = {0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E},
    ['1' - ' '] = {0x04, 0x0C, 0x14, 0x04, 0x04, 0x04, 0x1F},
    ['2' - ' '] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F},
    ['3' - ' '] = {0x1E, 0x01, 0x01, 0x0E, 0x01, 0x01, 0x1E},
    ['4' - ' '] = {0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02},
    ['5' - ' '] = {0x1F, 0x10, 0x10, 0x1E, 0x01, 0x01, 0x1E},
    ['6' - ' '] = {0x0E, 0x10, 0x10, 0x1E, 0x11, 0x11, 0x0E},
    ['7' - ' '] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08},
    ['8' - ' '] = {0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E},
    ['9' - ' '] = {0x0E, 0x11, 0x11, 0x0F, 0x01, 0x01, 0x0E},
    [':' - ' '] = {0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00},
    ['?' - ' '] = {0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04},
    ['A' - ' '] = {0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
    ['B' - ' '] = {0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E},
    ['C' - ' '] = {0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E},
    ['D' - ' '] = {0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E},
    ['E' - ' '] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F},
    ['F' - ' '] = {0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10},
    ['G' - ' '] = {0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F},
    ['H' - ' '] = {0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11},
    ['I' - ' '] = {0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E},
    ['J' - ' '] = {0x07, 0x02, 0x02, 0x02, 0x12, 0x12, 0x0C},
    ['K' - ' '] = {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11},
    ['L' - ' '] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F},
    ['M' - ' '] = {0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11},
    ['N' - ' '] = {0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11},
    ['O' - ' '] = {0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
    ['P' - ' '] = {0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10},
    ['Q' - ' '] = {0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D},
    ['R' - ' '] = {0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11},
    ['S' - ' '] = {0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E},
    ['T' - ' '] = {0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
    ['U' - ' '] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E},
    ['V' - ' '] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04},
    ['W' - ' '] = {0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11},
    ['X' - ' '] = {0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11},
    ['Y' - ' '] = {0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04},
    ['Z' - ' '] = {0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F},
};

static esp_err_t i2c_write(uint8_t control, const uint8_t *data, size_t len)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    if (cmd == NULL) {
        return ESP_ERR_NO_MEM;
    }
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (SSD1306_ADDR << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, control, true);
    i2c_master_write(cmd, (uint8_t *)data, len, true);
    i2c_master_stop(cmd);
    esp_err_t ret = i2c_master_cmd_begin(
        I2C_MASTER_NUM, cmd, pdMS_TO_TICKS(OLED_I2C_TIMEOUT_MS));
    i2c_cmd_link_delete(cmd);
    return ret;
}

static esp_err_t i2c_write_cmd(const uint8_t *data, size_t len)
{
    return i2c_write(0x00, data, len);
}

static esp_err_t i2c_write_data(const uint8_t *data, size_t len)
{
    return i2c_write(0x40, data, len);
}

static void set_pixel(int x, int y, bool on)
{
    if (x < 0 || x >= OLED_WIDTH || y < 0 || y >= OLED_HEIGHT) {
        return;
    }
    uint8_t mask = (uint8_t)(1u << (y & 7));
    uint8_t *cell = &fb[(y >> 3) * OLED_WIDTH + x];
    if (on) {
        *cell |= mask;
    } else {
        *cell &= (uint8_t)~mask;
    }
}

static void fill_rect(int x, int y, int width, int height, bool on)
{
    for (int py = y; py < y + height; py++) {
        for (int px = x; px < x + width; px++) {
            set_pixel(px, py, on);
        }
    }
}

static const uint8_t *glyph_for(char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        ch = (char)(ch - 'a' + 'A');
    }
    if (ch < ' ' || ch > 'Z') {
        ch = '?';
    }
    return font_5x7[(uint8_t)ch - ' '];
}

static void draw_char(int x, int y, char ch, int scale, bool on)
{
    const uint8_t *rows = glyph_for(ch);
    int output_rows = scale == 1 ? 8 : 7;
    for (int row = 0; row < output_rows; row++) {
        int source_row = (scale == 1 && row >= 4) ? row - 1 : row;
        for (int col = 0; col < 5; col++) {
            if ((rows[source_row] & (1u << (4 - col))) != 0) {
                fill_rect(x + col * scale, y + row * scale, scale, scale, on);
            }
        }
    }
}

static int text_width(const char *text, int scale)
{
    size_t len = text ? strlen(text) : 0;
    return len == 0 ? 0 : (int)(len * 6 * scale - scale);
}

static void draw_text(int x, int y, const char *text, int scale, bool on)
{
    if (text == NULL) {
        return;
    }
    for (size_t i = 0; text[i] != '\0'; i++) {
        draw_char(x, y, text[i], scale, on);
        x += 6 * scale;
    }
}

static void draw_text_centered(int y, const char *text, int scale, bool on)
{
    int x = (OLED_WIDTH - text_width(text, scale)) / 2;
    draw_text(x < 0 ? 0 : x, y, text, scale, on);
}

/* Eight large SCANNING glyphs fit in 127 pixels with one-pixel spacing.
 * Preserve the 15x21 glyph size rather than shrinking the main message. */
static void draw_scanning(void)
{
    const char *text = "SCANNING";
    for (int i = 0; text[i] != '\0'; i++) {
        draw_char(i * 16, 22, text[i], 3, true);
    }
}

static bool oled_flush(void)
{
    for (int page = 0; page < 8; page++) {
        const uint8_t page_cmds[] = {(uint8_t)(0xB0 | page), 0x00, 0x10};
        if (i2c_write_cmd(page_cmds, sizeof(page_cmds)) != ESP_OK ||
            i2c_write_data(&fb[page * OLED_WIDTH], OLED_WIDTH) != ESP_OK) {
            if (!transfer_error_logged) {
                ESP_LOGW(TAG, "Display transfer failed; suppressing repeated errors");
                transfer_error_logged = true;
            }
            return false;
        }
    }
    transfer_error_logged = false;
    return true;
}

static const char *attack_name(oled_attack_kind_t kind)
{
    switch (kind) {
    case OLED_ATTACK_DEAUTH: return "DEAUTH";
    case OLED_ATTACK_AUTH:   return "AUTH";
    case OLED_ATTACK_TWIN:   return "EVIL TWIN";
    case OLED_ATTACK_PROBE:  return "PROBE";
    case OLED_ATTACK_BEACON: return "BEACON";
    case OLED_ATTACK_ARP:    return "ARP";
    default:                 return "ANOMALY";
    }
}

static void draw_heading(const char *heading, bool inverted)
{
    if (inverted) {
        fill_rect(0, 0, OLED_WIDTH, 16, true);
        draw_text_centered(1, heading, 2, false);
    } else {
        draw_text_centered(1, heading, 2, true);
        fill_rect(0, 15, OLED_WIDTH, 1, true);
    }
}

/* Original 12x12 swallow silhouette: pointed wings and a forked tail.
 * Three poses follow an up / level / down / level wingbeat. */
static const uint16_t swallow_rows[3][12] = {
    {0x000, 0x020, 0x030, 0x838, 0x43A, 0x27F, 0x1FE, 0x2F8, 0x400, 0x800, 0x000, 0x000},
    {0x000, 0x000, 0x000, 0x800, 0x5F2, 0x27F, 0x1FE, 0x2F8, 0x4F8, 0x800, 0x000, 0x000},
    {0x000, 0x000, 0x000, 0x800, 0x402, 0x27F, 0x1FE, 0x2F8, 0x438, 0x830, 0x030, 0x020},
};

static void draw_swallow(uint32_t frame, bool inverted)
{
    static const uint8_t wingbeat[] = {0, 1, 2, 1};
    const uint16_t *rows = swallow_rows[wingbeat[frame % 4]];
    for (int y = 0; y < 12; y++) {
        for (int x = 0; x < 12; x++) {
            if (rows[y] & (1u << (11 - x))) {
                set_pixel(2 + x, 1 + y, !inverted);
            }
        }
    }
}

static void draw_activity(const oled_status_t *status, bool inverted, bool mascot)
{
    if (mascot) {
        draw_swallow(status->animation_frame, inverted);
    }
    /* UI heartbeat only, independent of packet volume and attack severity. */
    bool ink = !inverted;
    fill_rect(120, 5, 6, 6, ink);
    if (status->animation_frame % 2 == 0) {
        fill_rect(121, 6, 4, 4, !ink);
    }
}

static void draw_live_footer(const oled_status_t *status)
{
    if (status->wifi_connected && status->animation_frame % 6 >= 3) {
        char label[16];
        if (status->packets_per_second >= 1000000) {
            snprintf(label, sizeof(label), "1M+ PKT/S");
        } else if (status->packets_per_second >= 10000) {
            snprintf(label, sizeof(label), "%luK PKT/S",
                     (unsigned long)(status->packets_per_second / 1000));
        } else {
            snprintf(label, sizeof(label), "%lu PKT/S",
                     (unsigned long)status->packets_per_second);
        }
        draw_text_centered(50, label, 2, true);
    } else {
        draw_text_centered(50, status->wifi_connected ? "WIFI UP" : "WIFI DOWN", 2, true);
    }
}

bool oled_init(void)
{
    if (oled_ready) {
        return true;
    }
    const uint8_t init_seq[] = {
        0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40,
        0x8D, 0x14, 0xA1, 0xC8, 0xDA, 0x12, 0x81, 0xCF,
        0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6, 0xAF,
    };
    if (i2c_write_cmd(init_seq, sizeof(init_seq)) != ESP_OK) {
        ESP_LOGW(TAG, "SSD1306 not found at I2C address 0x%02X", SSD1306_ADDR);
        return false;
    }
    oled_ready = true;
    oled_clear();
    ESP_LOGI(TAG, "SSD1306 initialized");
    return true;
}

void oled_deinit(void)
{
    if (!oled_ready) {
        return;
    }
    const uint8_t command = 0xAE;
    i2c_write_cmd(&command, 1);
    oled_ready = false;
}

void oled_clear(void)
{
    memset(fb, 0, sizeof(fb));
    if (oled_ready) {
        oled_flush();
    }
}

void oled_show_status(const oled_status_t *status)
{
    if (!oled_ready || status == NULL) {
        return;
    }

    memset(fb, 0, sizeof(fb));

    /* Three clearly separated rows: state, main message, live link status.
     * Long attack names use scale 2; shorter names use scale 3. */
    switch (status->state) {
    case OLED_STATE_ALERT: {
        const char *name = attack_name(status->attack_kind);
        draw_heading(status->alarm_active ? "ATTACK" : "RECENT", true);
        draw_text_centered(22, name, text_width(name, 3) <= OLED_WIDTH ? 3 : 2, true);
        draw_activity(status, true, true);
        draw_text_centered(50, status->wifi_connected ? "WIFI UP" : "WIFI DOWN", 2, true);
        break;
    }

    case OLED_STATE_RECOVER:
        draw_heading("RECOVER", false);
        draw_activity(status, false, true);
        draw_scanning();
        draw_text_centered(50, "WIFI UP", 2, true);
        break;

    case OLED_STATE_LINK_DOWN:
        draw_heading("LINK LOST", true);
        draw_activity(status, true, false);
        draw_text_centered(22, "RETRY", 3, true);
        draw_text_centered(50, "WIFI DOWN", 2, true);
        break;

    case OLED_STATE_READY:
    default:
        draw_heading(status->calib_armed ? "NORMAL" : "STARTING", false);
        draw_activity(status, false, status->calib_armed);
        if (status->calib_armed) {
            draw_scanning();
        } else {
            draw_text_centered(22, "WAIT", 3, true);
        }
        draw_live_footer(status);
        break;
    }

    oled_flush();
}

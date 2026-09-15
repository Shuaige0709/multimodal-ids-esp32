#include "display.h"
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "oled.h"
#include "wifi_manager.h"

static const char *TAG = "DISPLAY";

void display_init(void)
{
    i2c_config_t i2c_conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = 21,
        .scl_io_num = 22,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = 400000,
    };
    ESP_ERROR_CHECK(i2c_param_config(I2C_NUM_0, &i2c_conf));
    ESP_ERROR_CHECK(i2c_driver_install(I2C_NUM_0, i2c_conf.mode, 0, 0, 0));
    ESP_LOGI(TAG, "I2C initialized for OLED");
}

void display_update(uint32_t pkt_count, uint32_t send_interval_packets, uint32_t free_heap, int8_t last_rssi,
                    uint32_t last_ipat, uint32_t stack_mark, uint32_t queue_depth, bool attack_detected)
{
    static bool oled_inited;
    static int64_t last_oled_update_ms;
    const int64_t OLED_UPDATE_MIN_INTERVAL_MS = 1500;
    if (!oled_inited) {
        ESP_LOGI(TAG, "Attempting OLED init...");
        oled_inited = oled_init();
        if (!oled_inited) {
            ESP_LOGW(TAG, "OLED init failed");
        } else {
            ESP_LOGI(TAG, "OLED init SUCCESS");
        }
    }
    if (oled_inited && (pkt_count % 200 == 0)) {
        int64_t now_ms = esp_timer_get_time() / 1000;
        if ((now_ms - last_oled_update_ms) >= OLED_UPDATE_MIN_INTERVAL_MS) {
            uint8_t current_channel = 0;
            wifi_second_chan_t secondary;
            esp_wifi_get_channel(&current_channel, &secondary);
            bool attack_flag = attack_detected; // driven by on-device inference
            oled_show_stats(wifi_manager_is_connected(), pkt_count, send_interval_packets, free_heap,
                            last_rssi, last_ipat, stack_mark, current_channel, wifi_manager_reconnect_count(),
                            queue_depth, attack_flag);
            last_oled_update_ms = now_ms;
        }
    }
}

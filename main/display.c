#include "display.h"

#include "driver/gpio.h"
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "net_config.h"
#include "nids_calib.h"
#include "oled.h"

static const char *TAG = "NIDS_INIT";

#if NIDS_OLED_ENABLE
static bool oled_init_attempted = false;
static bool oled_inited = false;
static int64_t last_oled_update_ms = 0;
static const int64_t OLED_UPDATE_MIN_INTERVAL_MS = 1000;
static const int64_t OLED_ALERT_HOLD_US = 8000000;
static const int64_t OLED_RECOVER_HOLD_US = 3000000;
static int64_t oled_alert_until_us = 0;
static int64_t oled_recover_until_us = 0;
static int8_t last_rssi = 0;
static oled_status_t oled_live = {0};
static oled_status_t oled_alert_snapshot = {0};
#endif

void display_prepare_bus(void)
{
#if NIDS_OLED_ENABLE
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
#else
    ESP_LOGI(TAG, "OLED disabled at compile time (NIDS_OLED_ENABLE=0)");
#endif
}

void display_note_rssi(int8_t rssi)
{
#if NIDS_OLED_ENABLE
    last_rssi = rssi;
#else
    (void)rssi;
#endif
}

void display_note_window(int raw_pred, int gated_pred, bool attack,
                         uint32_t packets, uint32_t deauth, uint32_t targeted,
                         uint32_t auth, uint32_t twin, uint32_t rogue)
{
#if NIDS_OLED_ENABLE
    oled_live.raw_pred = raw_pred;
    oled_live.gated_pred = gated_pred;
    oled_live.win_packets = packets;
    oled_live.win_deauth = deauth;
    oled_live.win_targeted = targeted;
    oled_live.win_auth = auth;
    oled_live.win_twin = twin;
    if (attack) {
        if (deauth > 0 || targeted > 0) {
            oled_live.attack_kind = OLED_ATTACK_DEAUTH;
        } else if (twin > 0 || rogue > 0) {
            oled_live.attack_kind = OLED_ATTACK_TWIN;
        } else if (auth > 0) {
            oled_live.attack_kind = OLED_ATTACK_AUTH;
        } else {
            oled_live.attack_kind = OLED_ATTACK_ANOMALY;
        }
        oled_alert_snapshot = oled_live;
        int64_t now_us = esp_timer_get_time();
        oled_alert_until_us = now_us + OLED_ALERT_HOLD_US;
        oled_recover_until_us = oled_alert_until_us + OLED_RECOVER_HOLD_US;
    }
#else
    (void)raw_pred;
    (void)gated_pred;
    (void)attack;
    (void)packets;
    (void)deauth;
    (void)targeted;
    (void)auth;
    (void)twin;
    (void)rogue;
#endif
}

void display_tick(bool wifi_up, bool collector_ready, uint8_t channel,
                  uint32_t reconnects, uint32_t backlog, uint32_t uart_drops)
{
#if NIDS_OLED_ENABLE
    if (!oled_init_attempted) {
        oled_init_attempted = true;
        ESP_LOGI(TAG, "Attempting OLED init...");
        oled_inited = oled_init();
        if (oled_inited) {
            ESP_LOGI(TAG, "OLED init SUCCESS");
        }
    }
    if (!oled_inited) {
        return;
    }
    int64_t now_ms = esp_timer_get_time() / 1000;
    if ((now_ms - last_oled_update_ms) < OLED_UPDATE_MIN_INTERVAL_MS) {
        return;
    }
    int64_t now_us = now_ms * 1000;
    oled_status_t view = oled_live;
    if (now_us < oled_alert_until_us) {
        view = oled_alert_snapshot;
        view.state = OLED_STATE_ALERT;
        view.hold_seconds = (uint32_t)((oled_alert_until_us - now_us + 999999) / 1000000);
    } else if (!wifi_up) {
        view.state = OLED_STATE_LINK_DOWN;
    } else if (now_us < oled_recover_until_us) {
        view = oled_alert_snapshot;
        view.state = OLED_STATE_RECOVER;
    } else {
        view.state = OLED_STATE_READY;
    }
    view.wifi_connected = wifi_up;
    view.collector_ready = collector_ready;
#if NIDS_CALIB_ENABLE
    view.calib_armed = nids_calib_state() == NIDS_CALIB_ARMED;
#else
    view.calib_armed = true;
#endif
    view.channel = channel;
    view.rssi = last_rssi;
    view.reconnects = reconnects;
    view.backlog = backlog;
    view.uart_drops = uart_drops;
    oled_show_status(&view);
    last_oled_update_ms = now_ms;
#else
    (void)wifi_up;
    (void)collector_ready;
    (void)channel;
    (void)reconnects;
    (void)backlog;
    (void)uart_drops;
#endif
}

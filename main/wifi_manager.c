#include "wifi_manager.h"

#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net_config.h"
#include "nids_gw.h"
#include "syslog_client.h"

static const char *TAG = "NIDS_INIT";

#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t wifi_event_group = NULL;
static volatile bool wifi_connected = false;
static uint32_t wifi_reconnect_count = 0;
static esp_timer_handle_t wifi_reconnect_timer = NULL;
static uint32_t wifi_reconnect_delay_ms = WIFI_RECONNECT_INITIAL_MS;

static char sta_mac_str[18] = "00:00:00:00:00:00";
static uint8_t sta_mac_bytes[6] = {0};
static char ap_bssid_str[18] = "00:00:00:00:00:00";
static uint8_t ap_bssid_bytes[6] = {0};
static char ap_ssid[33] = {0};
static uint8_t ap_ssid_len = 0;
static uint8_t ap_channel = 0;

static void schedule_wifi_reconnect(void)
{
    const uint32_t delay_ms = wifi_reconnect_delay_ms;

    if (wifi_reconnect_timer == NULL) {
        ESP_LOGW(TAG, "Reconnect timer unavailable; reconnecting immediately");
        esp_wifi_connect();
        return;
    }

    if (esp_timer_is_active(wifi_reconnect_timer)) {
        esp_timer_stop(wifi_reconnect_timer);
    }

    esp_err_t err = esp_timer_start_once(wifi_reconnect_timer, (uint64_t)delay_ms * 1000U);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not schedule WiFi reconnect: %s", esp_err_to_name(err));
        esp_wifi_connect();
        return;
    }

    if (wifi_reconnect_delay_ms < WIFI_RECONNECT_MAX_MS) {
        wifi_reconnect_delay_ms *= 2U;
        if (wifi_reconnect_delay_ms > WIFI_RECONNECT_MAX_MS) {
            wifi_reconnect_delay_ms = WIFI_RECONNECT_MAX_MS;
        }
    }
}

static void wifi_reconnect_timer_cb(void *arg)
{
    (void)arg;
    if (wifi_connected) {
        return;
    }
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Delayed WiFi reconnect failed: %s", esp_err_to_name(err));
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *event =
            (const wifi_event_sta_disconnected_t *)event_data;
        const unsigned reason = event ? (unsigned)event->reason : 0U;
        const uint32_t delay_ms = wifi_reconnect_delay_ms;
        wifi_connected = false;
        wifi_reconnect_count++;
        nids_gw_on_disconnect();
        ESP_LOGW(TAG,
                 "WiFi disconnected (reason=%u); pausing UDP sends, reconnect in %lu ms",
                 reason, (unsigned long)delay_ms);
        if (wifi_event_group) {
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
        schedule_wifi_reconnect();
        return;
    }

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        esp_netif_ip_info_t *ip_info = &event->ip_info;
        ESP_LOGI(TAG, "WiFi connected; resuming UDP sends");
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Netmask: " IPSTR ", Gateway: " IPSTR,
                 IP2STR(&ip_info->ip), IP2STR(&ip_info->netmask), IP2STR(&ip_info->gw));
        nids_gw_on_got_ip(ip_info->gw.addr);

        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            memcpy(ap_bssid_bytes, ap.bssid, 6);
            snprintf(ap_bssid_str, sizeof(ap_bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     ap.bssid[0], ap.bssid[1], ap.bssid[2],
                     ap.bssid[3], ap.bssid[4], ap.bssid[5]);
            ap_channel = ap.primary;
            ap_ssid_len = 0;
            while (ap_ssid_len < 32 && ap.ssid[ap_ssid_len] != 0) {
                ap_ssid[ap_ssid_len] = (char)ap.ssid[ap_ssid_len];
                ap_ssid_len++;
            }
            ap_ssid[ap_ssid_len] = '\0';
            if (ap_ssid_len == 0) {
                size_t n = strlen(WIFI_SSID);
                if (n > 32) {
                    n = 32;
                }
                memcpy(ap_ssid, WIFI_SSID, n);
                ap_ssid[n] = '\0';
                ap_ssid_len = (uint8_t)n;
            }
            ESP_LOGI(TAG, "AP BSSID: %s ch=%u ssid=%s", ap_bssid_str, ap_channel, ap_ssid);
        }

        esp_wifi_set_ps(WIFI_PS_NONE);
        wifi_connected = true;
        wifi_reconnect_delay_ms = WIFI_RECONNECT_INITIAL_MS;
        if (wifi_reconnect_timer && esp_timer_is_active(wifi_reconnect_timer)) {
            esp_timer_stop(wifi_reconnect_timer);
        }
        syslog_client_on_link_up();
        if (wifi_event_group) {
            xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
}

void wifi_manager_prepare(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    wifi_event_group = xEventGroupCreate();
    if (wifi_event_group == NULL) {
        ESP_LOGW(TAG, "Failed to create WiFi event group; falling back to fixed delay");
    }
}

void wifi_manager_start(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    const esp_timer_create_args_t reconnect_timer_args = {
        .callback = &wifi_reconnect_timer_cb,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "wifi_reconnect",
        .skip_unhandled_events = true,
    };
    ESP_ERROR_CHECK(esp_timer_create(&reconnect_timer_args, &wifi_reconnect_timer));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    uint8_t mac[6] = {0};
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
        memcpy(sta_mac_bytes, mac, 6);
        snprintf(sta_mac_str, sizeof(sta_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        ESP_LOGI(TAG, "STA MAC: %s", sta_mac_str);
    }

    ESP_LOGI(TAG, "Connecting to WiFi...");
    esp_wifi_connect();
    if (wifi_event_group == NULL) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_wifi_set_promiscuous(true);
    } else {
        EventBits_t bits = xEventGroupWaitBits(
            wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(10000));
        if (bits & WIFI_CONNECTED_BIT) {
            ESP_LOGI(TAG, "WiFi got IP (event). Enabling promiscuous mode");
        } else {
            ESP_LOGW(TAG, "Timed out waiting for IP; enabling promiscuous mode anyway");
        }
        esp_wifi_set_promiscuous(true);
    }
}

bool wifi_manager_is_connected(void)
{
    return wifi_connected;
}

uint32_t wifi_manager_reconnect_count(void)
{
    return wifi_reconnect_count;
}

const uint8_t *wifi_manager_sta_mac(void)
{
    return sta_mac_bytes;
}

const char *wifi_manager_sta_mac_str(void)
{
    return sta_mac_str;
}

const uint8_t *wifi_manager_ap_bssid(void)
{
    return ap_bssid_bytes;
}

const char *wifi_manager_ap_bssid_str(void)
{
    return ap_bssid_str;
}

const char *wifi_manager_ap_ssid(void)
{
    return ap_ssid;
}

uint8_t wifi_manager_ap_ssid_len(void)
{
    return ap_ssid_len;
}

uint8_t wifi_manager_ap_channel(void)
{
    return ap_channel;
}

void wifi_manager_force_disconnect(void)
{
    wifi_connected = false;
    esp_wifi_disconnect();
}

#include "wifi_manager.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

#include "net_config.h"
#include "nids_gw.h"

#define WIFI_CONNECTED_BIT BIT0

static const char *TAG = "WIFI_MGR";
static EventGroupHandle_t s_event_group;
static volatile bool s_connected;
static volatile bool s_connected_event;
static uint32_t s_reconnect_count;
static char s_sta_mac_str[18] = "00:00:00:00:00:00";
static uint8_t s_sta_mac[6];
static char s_ap_bssid_str[18] = "00:00:00:00:00:00";
static uint8_t s_ap_bssid[6];
static char s_ap_ssid[33];
static uint8_t s_ap_ssid_len;
static uint8_t s_ap_channel;

static void cache_ap_info(void)
{
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
        return;
    }

    memcpy(s_ap_bssid, ap.bssid, sizeof(s_ap_bssid));
    snprintf(s_ap_bssid_str, sizeof(s_ap_bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    s_ap_channel = ap.primary;
    s_ap_ssid_len = 0;
    while (s_ap_ssid_len < 32 && ap.ssid[s_ap_ssid_len] != 0) {
        s_ap_ssid[s_ap_ssid_len] = (char)ap.ssid[s_ap_ssid_len];
        s_ap_ssid_len++;
    }
    s_ap_ssid[s_ap_ssid_len] = '\0';
    if (s_ap_ssid_len == 0) {
        size_t len = strlen(WIFI_SSID);
        if (len > 32) len = 32;
        memcpy(s_ap_ssid, WIFI_SSID, len);
        s_ap_ssid[len] = '\0';
        s_ap_ssid_len = (uint8_t)len;
    }
    ESP_LOGI(TAG, "AP BSSID: %s ch=%u ssid=%s", s_ap_bssid_str, s_ap_channel, s_ap_ssid);
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        s_reconnect_count++;
        nids_gw_on_disconnect();
        xEventGroupClearBits(s_event_group, WIFI_CONNECTED_BIT);
        ESP_LOGW(TAG, "WiFi disconnected; reconnecting");
        esp_wifi_connect();
        return;
    }
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Netmask: " IPSTR ", Gateway: " IPSTR,
                 IP2STR(&event->ip_info.ip), IP2STR(&event->ip_info.netmask),
                 IP2STR(&event->ip_info.gw));
        nids_gw_on_got_ip(event->ip_info.gw.addr);
        cache_ap_info();
        esp_wifi_set_ps(WIFI_PS_NONE);
        s_connected = true;
        s_connected_event = true;
        xEventGroupSetBits(s_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_manager_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    s_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(s_event_group ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL));

    wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_config));
    wifi_config_t config = { .sta = { .ssid = WIFI_SSID, .password = WIFI_PASS } };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, s_sta_mac));
    snprintf(s_sta_mac_str, sizeof(s_sta_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             s_sta_mac[0], s_sta_mac[1], s_sta_mac[2], s_sta_mac[3], s_sta_mac[4], s_sta_mac[5]);
    ESP_LOGI(TAG, "STA MAC: %s; connecting", s_sta_mac_str);
    ESP_ERROR_CHECK(esp_wifi_connect());

    EventBits_t bits = xEventGroupWaitBits(s_event_group, WIFI_CONNECTED_BIT,
                                            pdFALSE, pdTRUE, pdMS_TO_TICKS(10000));
    if (bits & WIFI_CONNECTED_BIT) ESP_LOGI(TAG, "WiFi got IP");
    else ESP_LOGW(TAG, "Timed out waiting for IP; sniffing will still start");
}

bool wifi_manager_is_connected(void) { return s_connected; }
bool wifi_manager_take_connected_event(void)
{
    bool connected = s_connected_event;
    s_connected_event = false;
    return connected;
}
uint32_t wifi_manager_reconnect_count(void) { return s_reconnect_count; }
const uint8_t *wifi_manager_sta_mac(void) { return s_sta_mac; }
const char *wifi_manager_sta_mac_str(void) { return s_sta_mac_str; }
const uint8_t *wifi_manager_ap_bssid(void) { return s_ap_bssid; }
const char *wifi_manager_ap_bssid_str(void) { return s_ap_bssid_str; }
const char *wifi_manager_ap_ssid(void) { return s_ap_ssid; }
uint8_t wifi_manager_ap_ssid_len(void) { return s_ap_ssid_len; }
uint8_t wifi_manager_ap_channel(void) { return s_ap_channel; }

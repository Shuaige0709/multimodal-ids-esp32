#include "mitigation.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "net_config.h"
#include "wifi_manager.h"

static const char *TAG = "NIDS_SNIFFER";

#define MITIGATION_BLACKLIST_MAX 16
static uint8_t mitigation_blacklist[MITIGATION_BLACKLIST_MAX][6];
static uint32_t mitigation_blacklist_count = 0;
static uint32_t mitigation_events_total = 0;
static int64_t last_mitigation_us = 0;
static int64_t last_hips_disconnect_us = 0;

static bool mac_is_blacklisted(const uint8_t mac[6])
{
    for (uint32_t i = 0; i < mitigation_blacklist_count; i++) {
        if (memcmp(mitigation_blacklist[i], mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

void mitigation_on_attack(const nids_pkt_info_t *info)
{
    int64_t now = esp_timer_get_time();
    if (last_mitigation_us != 0 && (now - last_mitigation_us) < 2000000) {
        return;
    }
    last_mitigation_us = now;
    mitigation_events_total++;

    if (info && !mac_is_blacklisted(info->src_mac) &&
        mitigation_blacklist_count < MITIGATION_BLACKLIST_MAX) {
        memcpy(mitigation_blacklist[mitigation_blacklist_count], info->src_mac, 6);
        mitigation_blacklist_count++;
        ESP_LOGW(TAG, "[HIPS] Blacklisted attacker %02X:%02X:%02X:%02X:%02X:%02X (total=%lu)",
                 info->src_mac[0], info->src_mac[1], info->src_mac[2],
                 info->src_mac[3], info->src_mac[4], info->src_mac[5],
                 (unsigned long)mitigation_blacklist_count);
    }

    esp_wifi_set_ps(WIFI_PS_NONE);

#if HIPS_ENABLE_DISCONNECT
    if (last_hips_disconnect_us == 0 ||
        (now - last_hips_disconnect_us) > (int64_t)HIPS_DISCONNECT_COOLDOWN_MS * 1000) {
        last_hips_disconnect_us = now;
        ESP_LOGW(TAG, "[HIPS] Quarantine: temporary Wi-Fi disconnect (event #%lu)",
                 (unsigned long)mitigation_events_total);
        wifi_manager_force_disconnect();
    }
#else
    (void)now;
#endif
}

uint32_t mitigation_event_count(void)
{
    return mitigation_events_total;
}

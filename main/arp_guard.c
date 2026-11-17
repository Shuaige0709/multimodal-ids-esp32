/* ARP repair is executed on lwIP's TCP/IP thread, not the sniffer task.
 * A separate low-priority task verifies gateway reachability with ICMP. */
#include "arp_guard.h"
#include "arp_guard_config.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "ping/ping_sock.h"
#include "wifi_manager.h"

static const char *TAG = "ARP_GUARD";
typedef struct {
    ip4_addr_t gateway;
    uint8_t trusted[6], observed[6], bssid[6];
    bool found, install, remove;
    err_t result;
} arp_operation_t;

/* These callbacks are synchronous through tcpip_callback_wait. */
static void arp_access(void *arg)
{
    arp_operation_t *op = arg;
    struct eth_addr *mac = NULL;
    const ip4_addr_t *ip = NULL;
    op->found = false;
#if ETHARP_SUPPORT_STATIC_ENTRIES
    if (op->remove) {
        op->result = etharp_remove_static_entry(&op->gateway);
        return;
    }
#endif
    if (!netif_default || netif_ip4_gw(netif_default)->addr != op->gateway.addr) {
        op->result = ERR_RTE;
        return;
    }
    op->result = ERR_OK;
#if ETHARP_SUPPORT_STATIC_ENTRIES
    if (op->install) {
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK || memcmp(ap.bssid, op->bssid, 6) != 0) {
            op->result = ERR_RTE;
            return;
        }
        struct eth_addr trusted;
        memcpy(trusted.addr, op->trusted, 6);
        op->result = etharp_add_static_entry(&op->gateway, &trusted);
    }
#else
    if (op->install || op->remove) op->result = ERR_IF;
#endif
    if (etharp_find_addr(netif_default, &op->gateway, &mac, &ip) >= 0 && mac) {
        memcpy(op->observed, mac->addr, 6);
        op->found = true;
    } else {
        etharp_request(netif_default, &op->gateway);
    }
}

static bool parse_mac(const char *text, uint8_t out[6])
{
    unsigned b[6];
    int n = 0;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%n",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &n) != 6 ||
        n != 17 || text[n] != '\0') return false;
    unsigned any = 0;
    for (int i = 0; i < 6; i++) { out[i] = (uint8_t)b[i]; any |= b[i]; }
    return any && !(out[0] & 1);
}

typedef struct { TaskHandle_t task; volatile bool replied; } probe_context_t;
static void probe_success(esp_ping_handle_t handle, void *arg)
{
    (void)handle;
    ((probe_context_t *)arg)->replied = true;
}
static void probe_end(esp_ping_handle_t handle, void *arg)
{
    (void)handle;
    xTaskNotifyGive(((probe_context_t *)arg)->task);
}

static void guard_task(void *arg)
{
    (void)arg;
    ip4_addr_t gateway;
    uint8_t trusted[6], bssid[6];
    bool configured = ip4addr_aton(ARP_GUARD_GATEWAY_IP, &gateway) &&
                      gateway.addr && parse_mac(ARP_GUARD_GATEWAY_MAC, trusted) &&
                      parse_mac(ARP_GUARD_BSSID, bssid);
    if (!configured) {
        while (1) {
            ESP_LOGW(TAG, "[ARP_GUARD] mode=%s action=invalid repairs=0 err=0",
                     ARP_GUARD_ENABLE ? "on" : "off");
            vTaskDelay(pdMS_TO_TICKS(2000));
        }
    }
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    ip_addr_copy_from_ip4(cfg.target_addr, gateway);
    cfg.count = 1;
    cfg.interval_ms = 100;
    cfg.timeout_ms = 700;
    cfg.data_size = 24;
    probe_context_t probe = {.task = xTaskGetCurrentTaskHandle()};
    esp_ping_callbacks_t callbacks = {
        .cb_args = &probe, .on_ping_success = probe_success, .on_ping_end = probe_end
    };
    esp_ping_handle_t ping = NULL;
    esp_err_t ping_error = esp_ping_new_session(&cfg, &callbacks, &ping);
    bool locked = false, armed_after_reconnect = false;
    uint32_t repairs = 0, sent = 0, received = 0;
    while (1) {
        esp_netif_ip_info_t info = {0};
        esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        wifi_ap_record_t ap;
        bool scope = wifi_manager_is_connected() && sta &&
                     esp_netif_get_ip_info(sta, &info) == ESP_OK &&
                     info.gw.addr == gateway.addr && esp_wifi_sta_get_ap_info(&ap) == ESP_OK &&
                     memcmp(ap.bssid, bssid, 6) == 0;
        arp_operation_t op = {.gateway = gateway};
        memcpy(op.trusted, trusted, 6);
        memcpy(op.bssid, bssid, 6);
        if (!scope) {
            /* Never leave a pinned entry active across a different AP/profile.
             * If disconnected lwIP may already have removed it. */
            if (locked) {
                op.remove = true;
                tcpip_callback_wait(arp_access, &op);
                armed_after_reconnect = true;
            }
            locked = false;
            ESP_LOGI(TAG, "[ARP_GUARD] mode=%s action=waiting repairs=%lu err=0",
                     ARP_GUARD_ENABLE ? "on" : "off", (unsigned long)repairs);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        err_t dispatched = tcpip_callback_wait(arp_access, &op);
        bool mismatch = dispatched == ERR_OK && op.result == ERR_OK && op.found &&
                        memcmp(op.observed, trusted, 6) != 0;
        bool repair = ARP_GUARD_ENABLE && (mismatch || armed_after_reconnect ||
                                          (locked && !op.found));
        if (mismatch) {
            ESP_LOGW(TAG, "[ARP_GUARD_EVENT] mismatch=1 observed=%02X:%02X:%02X:%02X:%02X:%02X",
                     op.observed[0], op.observed[1], op.observed[2],
                     op.observed[3], op.observed[4], op.observed[5]);
        }
        if (repair) {
            op.install = true;
            dispatched = tcpip_callback_wait(arp_access, &op);
            locked = dispatched == ERR_OK && op.result == ERR_OK && op.found &&
                     memcmp(op.observed, trusted, 6) == 0;
            if (locked) { repairs++; armed_after_reconnect = false; }
            else if (op.result == ERR_OK) op.result = ERR_VAL;
        }
        /* Log independently of ICMP results; installing a rule is not recovery. */
        ESP_LOGI(TAG, "[ARP_GUARD] mode=%s action=%s repairs=%lu err=%d ip=" IPSTR,
                 ARP_GUARD_ENABLE ? "on" : "off",
                 dispatched != ERR_OK || op.result != ERR_OK ? "error" :
                 locked ? "locked" : mismatch ? "detected" : "watch",
                 (unsigned long)repairs, (int)(dispatched != ERR_OK ? dispatched : op.result),
                 IP2STR(&info.ip));
        if (ping_error != ESP_OK) {
            ESP_LOGW(TAG, "[ARP_PROBE] target=" IPSTR " result=error sent=%lu received=%lu repair=%lu",
                     IP2STR(&gateway), (unsigned long)sent, (unsigned long)received,
                     (unsigned long)repairs);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        probe.replied = false;
        esp_err_t start = esp_ping_start(ping);
        if (start == ESP_OK) {
            /* Only this low-priority worker waits. Ping owns its timeout;
             * neither the Wi-Fi callback nor 100-ms inference task waits here. */
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            sent++;
            if (probe.replied) received++;
        }
        /* A link change during the probe invalidates that result. */
        if (!wifi_manager_is_connected() || esp_wifi_sta_get_ap_info(&ap) != ESP_OK ||
            memcmp(ap.bssid, bssid, 6) != 0 ||
            esp_netif_get_ip_info(sta, &info) != ESP_OK || info.gw.addr != gateway.addr) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        ESP_LOGI(TAG, "[ARP_PROBE] target=" IPSTR " result=%s sent=%lu received=%lu repair=%lu",
                 IP2STR(&gateway), start != ESP_OK ? "error" : probe.replied ? "ok" : "timeout",
                 (unsigned long)sent, (unsigned long)received, (unsigned long)repairs);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void arp_guard_start(void)
{
    BaseType_t created = xTaskCreate(guard_task, "arp_guard", 4096, NULL, 2, NULL);
    ESP_ERROR_CHECK(created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
}

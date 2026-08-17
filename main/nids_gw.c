#include "nids_gw.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"

static const char *TAG = "NIDS_GW";

static bool s_have_gw;
static ip4_addr_t s_gw;
static bool s_have_mac;
static uint8_t s_mac[6];
static uint32_t s_flip;
static char s_mac_str[18];
static int64_t s_last_req_us;

void nids_gw_on_got_ip(uint32_t gw_addr)
{
    s_have_mac = false;
    s_flip = 0;
    s_mac_str[0] = '-';
    s_mac_str[1] = '\0';
    if (gw_addr == 0) {
        s_have_gw = false;
        return;
    }
    s_gw.addr = gw_addr;
    s_have_gw = true;
    ESP_LOGI(TAG, "watching gateway " IPSTR, IP2STR(&s_gw));
}

void nids_gw_on_disconnect(void)
{
    s_have_gw = false;
    s_have_mac = false;
}

static void format_mac(void)
{
    if (!s_have_mac) {
        s_mac_str[0] = '-';
        s_mac_str[1] = '\0';
        return;
    }
    snprintf(s_mac_str, sizeof(s_mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
}

void nids_gw_poll(void)
{
    if (!s_have_gw || !netif_default) {
        return;
    }

    struct eth_addr *eth = NULL;
    const ip4_addr_t *ip_ret = NULL;
    if (etharp_find_addr(netif_default, &s_gw, &eth, &ip_ret) < 0 || !eth) {
        int64_t now = esp_timer_get_time();
        if (now - s_last_req_us > 2000000) {
            etharp_request(netif_default, &s_gw);
            s_last_req_us = now;
        }
        return;
    }

    const uint8_t *m = eth->addr;
    if ((m[0]|m[1]|m[2]|m[3]|m[4]|m[5]) == 0) {
        return;
    }

    if (!s_have_mac) {
        memcpy(s_mac, m, 6);
        s_have_mac = true;
        format_mac();
        ESP_LOGI(TAG, "gateway MAC %s", s_mac_str);
        return;
    }

    if (memcmp(s_mac, m, 6) != 0) {
        s_flip++;
        memcpy(s_mac, m, 6);
        format_mac();
        ESP_LOGW(TAG, "*** GW MAC FLIP *** now %s (n=%lu)",
                 s_mac_str, (unsigned long)s_flip);
    }
}

uint32_t nids_gw_flip(void)
{
    return s_flip;
}

const char *nids_gw_mac_str(void)
{
    if (!s_have_mac) {
        return "-";
    }
    return s_mac_str;
}

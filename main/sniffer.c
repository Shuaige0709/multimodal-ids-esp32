#include "sniffer.h"

#include <string.h>

#include "app_config.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net_config.h"
#include "nids_types.h"
#include "wifi_manager.h"

static const char *TAG = "NIDS_SNIFFER";

static QueueHandle_t pkt_info_queue = NULL;
static uint32_t last_timestamp = 0;
static uint16_t last_seq_seen = 0;
static bool last_seq_valid = false;
static volatile uint32_t rx_queue_drop_total = 0;

static uint8_t mgmt_ssid_matches_ours(const uint8_t *payload, uint32_t len)
{
    const char *want;
    uint8_t nwant;
    if (wifi_manager_ap_ssid_len() > 0) {
        want = wifi_manager_ap_ssid();
        nwant = wifi_manager_ap_ssid_len();
    } else {
        size_t n = strlen(WIFI_SSID);
        if (n > 32) {
            n = 32;
        }
        want = WIFI_SSID;
        nwant = (uint8_t)n;
    }
    if (nwant == 0 || len < 38 || payload == NULL) {
        return 0;
    }
    uint32_t off = 36;
    for (int i = 0; i < 32 && off + 2 <= len; i++) {
        uint8_t tag = payload[off];
        uint8_t tlen = payload[off + 1];
        if (off + 2u + tlen > len) {
            break;
        }
        if (tag == 0) {
            if (tlen == nwant && memcmp(payload + off + 2, want, nwant) == 0) {
                return 1;
            }
            return 0;
        }
        off += 2u + tlen;
    }
    return 0;
}

static void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    nids_pkt_info_t info = {0};

    info.timestamp = pkt->rx_ctrl.timestamp;
    info.ipat = (last_timestamp == 0 || info.timestamp < last_timestamp) ? 0 : (info.timestamp - last_timestamp);
    last_timestamp = info.timestamp;
    info.rssi = pkt->rx_ctrl.rssi;
    info.snr = pkt->rx_ctrl.rssi - pkt->rx_ctrl.noise_floor;
    info.rate = pkt->rx_ctrl.rate;
    info.mcs = pkt->rx_ctrl.mcs;
    info.len = pkt->rx_ctrl.sig_len;

    switch (type) {
    case WIFI_PKT_MGMT: strcpy(info.type_str, "MGMT"); break;
    case WIFI_PKT_CTRL: strcpy(info.type_str, "CTRL"); break;
    case WIFI_PKT_DATA: strcpy(info.type_str, "DATA"); break;
    case WIFI_PKT_MISC: strcpy(info.type_str, "MISC"); break;
    default: strcpy(info.type_str, "OTHER"); break;
    }

    if (info.len >= 16) {
        memcpy(info.dst_mac, pkt->payload + 4, 6);
        memcpy(info.src_mac, pkt->payload + 10, 6);
    }
    if (info.len >= 22) {
        memcpy(info.bssid, pkt->payload + 16, 6);
    }
    info.seq_ctrl = (info.len >= 24) ? (((pkt->payload[23] << 8) | pkt->payload[22]) >> 4) : 0;

    if (info.len >= 24) {
        uint16_t seq = info.seq_ctrl & 0x0FFF;
        if (last_seq_valid) {
            uint16_t d = (uint16_t)((seq - last_seq_seen) & 0x0FFF);
            if (d > SEQ_JUMP_THRESH && d < (4096 - SEQ_JUMP_THRESH)) {
                info.seq_jump = 1;
            }
        }
        last_seq_seen = seq;
        last_seq_valid = true;
    }

    if (info.len >= 1) {
        uint8_t fc0 = pkt->payload[0];
        uint8_t frame_type = (fc0 >> 2) & 0x3;
        uint8_t fc_subtype = (fc0 >> 4) & 0xF;
        if (frame_type == 0) {
            switch (fc_subtype) {
            case 4: strcpy(info.subtype, "PROBE_REQ"); break;
            case 5: strcpy(info.subtype, "PROBE_RESP"); break;
            case 8: strcpy(info.subtype, "BEACON"); break;
            case 10: strcpy(info.subtype, "DISASSOC"); break;
            case 11: strcpy(info.subtype, "AUTH"); break;
            case 12: strcpy(info.subtype, "DEAUTH"); break;
            default: strcpy(info.subtype, "MGMT_OTHER"); break;
            }
            if (fc_subtype == 10 || fc_subtype == 12) {
                static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (memcmp(info.dst_mac, bcast, 6) == 0 ||
                    memcmp(info.dst_mac, wifi_manager_sta_mac(), 6) == 0) {
                    info.deauth_targeted = 1;
                }
            }
            if (fc_subtype == 5 || fc_subtype == 8) {
                info.ssid_ours = mgmt_ssid_matches_ours(pkt->payload, info.len);
            }
        }
    }

    if (pkt_info_queue == NULL || xQueueSend(pkt_info_queue, &info, 0) != pdTRUE) {
        rx_queue_drop_total++;
    }
}

void sniffer_prepare(void)
{
    pkt_info_queue = xQueueCreate(SNIFFER_QUEUE_LENGTH, sizeof(nids_pkt_info_t));
    ESP_ERROR_CHECK(pkt_info_queue ? ESP_OK : ESP_ERR_NO_MEM);
}

QueueHandle_t sniffer_queue(void)
{
    return pkt_info_queue;
}

uint32_t sniffer_drop_count(void)
{
    return rx_queue_drop_total;
}

void sniffer_start(void)
{
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    ESP_LOGI(TAG, "Promiscuous mode enabled. Sniffing packets...");

    if (CHANNEL_HOP_MODE == 1) {
        ESP_LOGI(TAG, "Starting channel hopping...");
        uint8_t channel = 1;
        while (1) {
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            ESP_LOGI(TAG, "Switched to channel %d", channel);
            channel = (channel % 13) + 1;
            vTaskDelay(pdMS_TO_TICKS(10000));
        }
    }

    uint8_t channel = 11;
    ESP_LOGI(TAG, "SET ESP32 at channel %d to collect dataset", channel);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

#include "sniffer.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "app_config.h"
#include "net_config.h"
#include "wifi_manager.h"

static const char *TAG2 = "NIDS_SNIFFER";
static sniffer_packet_sink_t s_packet_sink;
static uint32_t last_timestamp;
static uint16_t last_seq_seen;
static bool last_seq_valid;

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

// This callback will be called for each received WiFi packet in promiscuous mode
static void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    // wifi_promiscuous_pkt_t is the structure of the received packet in
    // promiscuous mode, it contains metadata and payload
    // rx_ctrl is the metadata header, which contains RSSI, channel, timestamp, etc.
    // payload is the actual packet data (802.11), which can be parsed according to the packet type
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    nids_pkt_info_t info;

    // extract common metadata for all packet types
    info.timestamp = pkt->rx_ctrl.timestamp;
    info.ipat =
        (last_timestamp == 0 || info.timestamp < last_timestamp) ? 0 : (info.timestamp - last_timestamp);
    last_timestamp = info.timestamp;

    info.rssi = pkt->rx_ctrl.rssi;
    info.snr = pkt->rx_ctrl.rssi - pkt->rx_ctrl.noise_floor;
    info.rate = pkt->rx_ctrl.rate;
    info.mcs = pkt->rx_ctrl.mcs;
    info.len = pkt->rx_ctrl.sig_len;

    // extract packet type
    // MGMT: management frame, CTRL: control frame, DATA: data frame, MISC: other type (e.g. MIMO)
    switch (type) {
    case WIFI_PKT_MGMT:
        strcpy(info.type_str, "MGMT");
        break;
    case WIFI_PKT_CTRL:
        strcpy(info.type_str, "CTRL");
        break;
    case WIFI_PKT_DATA:
        strcpy(info.type_str, "DATA");
        break;
    case WIFI_PKT_MISC:
        strcpy(info.type_str, "MISC");
        break;
    default:
        strcpy(info.type_str, "OTHER");
        break;
    }

    // 802.11 addrs: addr1=dst @4, addr2=src @10 (mgmt/data)
    if (info.len >= 16) {
        memcpy(info.dst_mac, pkt->payload + 4, 6);
        memcpy(info.src_mac, pkt->payload + 10, 6);
    } else {
        memset(info.dst_mac, 0, 6);
        memset(info.src_mac, 0, 6);
    }
    if (info.len >= 22) {
        memcpy(info.bssid, pkt->payload + 16, 6);
    } else {
        memset(info.bssid, 0, 6);
    }

    // 802.11 header
    info.seq_ctrl = (info.len >= 24) ? (((pkt->payload[23] << 8) | pkt->payload[22]) >> 4)
                                     : 0; // sequence control field is located at offset 22-23 in the 802.11
                                          // header for both management and data frames

    // P0: sequence jump vs previous frame (wrap-aware, 12-bit seq)
    info.seq_jump = 0;
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

    info.deauth_targeted = 0;
    info.ssid_ours = 0;

    // Parse 802.11 Frame Control to extract subtype when possible
    if (info.len >= 1) {
        uint8_t fc0 = pkt->payload[0];
        uint8_t frame_type = (fc0 >> 2) & 0x3; // 0=Mgmt,1=Ctrl,2=Data
        uint8_t fc_subtype = (fc0 >> 4) & 0xF;
        if (frame_type == 0) { // Management frames
            switch (fc_subtype) {
            case 4:
                strcpy(info.subtype, "PROBE_REQ");
                break;
            case 5:
                strcpy(info.subtype, "PROBE_RESP");
                break;
            case 8:
                strcpy(info.subtype, "BEACON");
                break;
            case 10:
                strcpy(info.subtype, "DISASSOC");
                break;
            case 11:
                strcpy(info.subtype, "AUTH"); // proxy for EAP / auth-based frames
                break;
            case 12:
                strcpy(info.subtype, "DEAUTH");
                break;
            default:
                strcpy(info.subtype, "MGMT_OTHER");
                break;
            }
            // P0: deauth/disassoc aimed at this STA or broadcast (ignore side-channel noise)
            if (fc_subtype == 10 || fc_subtype == 12) {
                static const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                if (memcmp(info.dst_mac, bcast, 6) == 0 ||
                    memcmp(info.dst_mac, wifi_manager_sta_mac(), 6) == 0) {
                    info.deauth_targeted = 1;
                }
            }
            // Beacon / probe response: SSID IE vs associated AP (evil-twin identity).
            if (fc_subtype == 5 || fc_subtype == 8) {
                info.ssid_ours = mgmt_ssid_matches_ours(pkt->payload, info.len);
            }
        } else {
            info.subtype[0] = '\0';
        }
    } else {
        info.subtype[0] = '\0';
    }

    s_packet_sink(&info);

    // optional metadata
    // pkt->rx_ctrl.aggregation;
    // pkt->rx_ctrl.stbc;
    // pkt->rx_ctrl.fec_coding;
    // pkt->rx_ctrl.sgi;
    // pkt->rx_ctrl.rate;
    // pkt->rx_ctrl.mcs;
}

#if CHANNEL_HOP_MODE
static void channel_hop_task(void *arg)
{
    (void)arg;
    uint8_t channel = 1;
    while (1) {
        esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        if (err != ESP_OK)
            ESP_LOGW(TAG2, "Channel %u: %s", channel, esp_err_to_name(err));
        channel = (channel % 13) + 1;
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
#endif

void sniffer_start(sniffer_packet_sink_t sink)
{
    ESP_ERROR_CHECK(sink ? ESP_OK : ESP_ERR_INVALID_ARG);
    s_packet_sink = sink;
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_callback));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_LOGI(TAG2, "Promiscuous mode enabled. Sniffing packets...");
#if CHANNEL_HOP_MODE
    ESP_ERROR_CHECK(xTaskCreate(channel_hop_task, "channel_hop", 2048, NULL, 5, NULL) == pdPASS
                        ? ESP_OK
                        : ESP_ERR_NO_MEM);
#else
    // Preserves the dataset capture policy; the AP should use this channel too.
    esp_err_t err = esp_wifi_set_channel(SNIFFER_FIXED_CHANNEL, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK)
        ESP_LOGW(TAG2, "Set capture channel: %s", esp_err_to_name(err));
#endif
}

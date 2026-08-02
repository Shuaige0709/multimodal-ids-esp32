#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "lwip/sockets.h"
#include "string.h"
#include <errno.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "oled.h"
#include "esp_http_server.h"
#include "driver/uart.h"

#include "net_config.h"   // WIFI_SSID/PASS, ports, auto-discovery settings (single source of truth)
#include "model.h"        // generated on-device inference model (nids_window_features_t / nids_predict)

#define SYSLOG_PRI 14      // Facility: User(1) * 8 + Severity: Info(6)
#define VERSION "1"
#define HOSTNAME "esp32-node"
#define APP_NAME "NIDS_PROBE"
#define PEN "45917"        // Private Enterprise Number for ESP32 (may apply from IANA later)
#define SYSlOG_MODE 1         // 0: print to console, 1: send via UDP, 2: send via UART/USB serial
#define CHANNEL_HOP_MODE 0 // 0: fixed channel, 1: channel hopping
#define DATASET_PROFILE 1   // 1: higher-throughput collection, 0: runtime-balanced profile

static const char *TAG = "NIDS_INIT";
static const char *TAG2 = "NIDS_SNIFFER";

// Event group to signal when WiFi has obtained an IP
#define WIFI_CONNECTED_BIT BIT0
static EventGroupHandle_t wifi_event_group = NULL;

static volatile bool wifi_connected = false;
static uint32_t wifi_reconnect_count = 0;
static uint32_t send_interval_packets = 10;
static uint32_t consecutive_send_failures = 0;
static uint32_t consecutive_send_successes = 0;
static uint32_t udp_send_failure_total = 0;
static uint32_t udp_send_success_total = 0;
static bool syslog_first_tx_logged = false;
static const uint32_t SEND_INTERVAL_FAST = DATASET_PROFILE ? 50 : 20;
static const uint32_t SEND_INTERVAL_SLOW = DATASET_PROFILE ? 100 : 50;
static const uint32_t SEND_FAIL_THRESHOLD = 3;
static const uint32_t SEND_RECOVER_THRESHOLD = 10;
/* Keep backlog RAM ~same as before (was 512×256): fewer slots, longer lines. */
static const uint32_t SYSLOG_BACKLOG_MAX = DATASET_PROFILE ? 256 : 128;
static const uint32_t SYSLOG_FLUSH_BUDGET = DATASET_PROFILE ? 32 : 16;
static const uint32_t SYSLOG_MSG_MAX = 512;

static char syslog_backlog[256][512];
static uint32_t syslog_backlog_head = 0;
static uint32_t syslog_backlog_tail = 0;
static uint32_t syslog_backlog_count = 0;
static uint32_t syslog_backlog_dropped = 0;
static uint32_t queue_peak_depth = 0;

// --- Collector auto-discovery state (learned from UDP broadcast beacon) ---
static volatile bool collector_discovered = false;
static volatile uint32_t collector_ip_be = 0;                 // collector IP in network byte order
static volatile uint16_t collector_log_port = SYSLOG_PORT;    // collector syslog port (learned or default)

// Own STA MAC (filled once Wi-Fi has started), used in syslog + deauth_targeted
static char sta_mac_str[18] = "00:00:00:00:00:00";
static uint8_t sta_mac_bytes[6] = {0};

// Associated AP identity for live_state.json (filled on GOT_IP)
static char ap_bssid_str[18] = "00:00:00:00:00:00";
static uint8_t ap_channel = 0;

// Sequence-jump detector state (P0 WIDS)
#define SEQ_JUMP_THRESH 64
static uint16_t last_seq_seen = 0;
static bool last_seq_valid = false;

// --- On-device 100 ms window aggregation + inference state ---
static volatile bool attack_detected = false;                 // latest inference result (drives OLED / mitigation)
static volatile uint32_t last_inference_us = 0;               // most recent inference latency (microseconds)

static bool send_syslog_udp(int sock, struct sockaddr_in *dest_addr, const char *buffer);
static void serial_init(void);
static void send_syslog_serial(const char *buffer);
static bool resolve_collector(struct sockaddr_in *dest_addr);

typedef struct{
    uint32_t timestamp; // packet timestamp
    uint32_t ipat; // inter-packet arrival time in microseconds
    int8_t rssi; // signal strength in dBm
    int8_t snr; // signal-to-noise ratio in dB
    uint8_t rate; // PHY rate encoding
    uint16_t seq_ctrl; // sequence control field from 802.11 header
    uint8_t mcs; // modulation coding scheme for HT/VHT packets
    uint32_t len; // packet length
    uint8_t src_mac[6]; // source MAC address (addr2)
    uint8_t dst_mac[6]; // destination MAC address (addr1)
    uint8_t deauth_targeted; // 1 if DEAUTH/DISASSOC to us or broadcast
    uint8_t seq_jump; // 1 if sequence number jumped vs previous frame
    char type_str[8]; // packet type (MGMT, CTRL, DATA, MISC) 
    char subtype[16]; // detailed subtype (e.g., BEACON, PROBE_REQ)
} nids_pkt_info_t;

static QueueHandle_t pkt_info_queue = NULL; // queue to store packet info for processing
static uint32_t last_timestamp = 0; // global variable to store timestamp of the last received packet for calculating inter-arrival time (IPAT)

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = false;
        wifi_reconnect_count++;
        ESP_LOGW(TAG, "WiFi disconnected; pausing UDP sends and reconnecting");
        if (wifi_event_group) {
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
        esp_wifi_connect();
        return;
    }

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        // Log the acquired IP address, netmask and gateway for easy verification
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
        esp_netif_ip_info_t *ip_info = &event->ip_info;
        ESP_LOGI(TAG, "WiFi connected; resuming UDP sends");
        ESP_LOGI(TAG, "Got IP: " IPSTR ", Netmask: " IPSTR ", Gateway: " IPSTR,
                 IP2STR(&ip_info->ip), IP2STR(&ip_info->netmask), IP2STR(&ip_info->gw));

        /* Cache AP BSSID + channel for live_state / deauth scripts. */
        {
            wifi_ap_record_t ap;
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
                snprintf(ap_bssid_str, sizeof(ap_bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                         ap.bssid[0], ap.bssid[1], ap.bssid[2],
                         ap.bssid[3], ap.bssid[4], ap.bssid[5]);
                ap_channel = ap.primary;
                ESP_LOGI(TAG, "AP BSSID: %s ch=%u", ap_bssid_str, ap_channel);
            }
        }

        /* Lab: disable modem sleep so UDP syslog is more reliable while sniffing. */
        esp_wifi_set_ps(WIFI_PS_NONE);

        wifi_connected = true;
        consecutive_send_failures = 0;
        consecutive_send_successes = 0;
        send_interval_packets = SEND_INTERVAL_FAST;
        if (wifi_event_group) {
            xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
}

// Resolve the current collector destination.
// Prefers an auto-discovered collector; optionally falls back to a static IP.
// Returns false when no destination is known yet (caller should buffer to backlog).
static bool resolve_collector(struct sockaddr_in *dest_addr)
{
    dest_addr->sin_family = AF_INET;
    if (collector_discovered) {
        dest_addr->sin_addr.s_addr = collector_ip_be;
        dest_addr->sin_port = htons(collector_log_port);
        return true;
    }
    /* Fallback even while waiting for beacon (non-empty COLLECTOR_FALLBACK_IP). */
    if (COLLECTOR_FALLBACK_IP[0] != '\0') {
        dest_addr->sin_addr.s_addr = inet_addr(COLLECTOR_FALLBACK_IP);
        dest_addr->sin_port = htons(SYSLOG_PORT);
        return (dest_addr->sin_addr.s_addr != INADDR_NONE &&
                dest_addr->sin_addr.s_addr != 0);
    }
    return false;
}

// Function to send syslog message via UDP to a remote server (such as kiwi syslog server)
static bool send_syslog_udp(int sock, struct sockaddr_in *dest_addr, const char *buffer) {
    int err = sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr));
    if (err < 0) {
        if (errno == ENOMEM || errno == 118) {
            // lwIP tx buffer may be temporarily exhausted; short backoff then retry once.
            vTaskDelay(pdMS_TO_TICKS(10));
            err = sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr));
        }
    }

    if (err < 0) {
        consecutive_send_failures++;
        udp_send_failure_total++;
        consecutive_send_successes = 0;
        if (consecutive_send_failures >= SEND_FAIL_THRESHOLD) {
            send_interval_packets = SEND_INTERVAL_SLOW;
        }
        ESP_LOGW("UDP", "Error occurred during sending: errno %d", errno);
        if (!syslog_first_tx_logged) {
            syslog_first_tx_logged = true;
            ESP_LOGW(TAG2, "First syslog UDP TX FAILED → %s:%u errno=%d",
                     inet_ntoa(dest_addr->sin_addr),
                     (unsigned)ntohs(dest_addr->sin_port), errno);
        }
        return false;
    } else {
        udp_send_success_total++;
        consecutive_send_failures = 0;
        consecutive_send_successes++;
        if (!syslog_first_tx_logged) {
            syslog_first_tx_logged = true;
            ESP_LOGI(TAG2, "First syslog UDP TX OK → %s:%u (sendto accepted; Pi must listen :%u)",
                     inet_ntoa(dest_addr->sin_addr),
                     (unsigned)ntohs(dest_addr->sin_port),
                     (unsigned)ntohs(dest_addr->sin_port));
        }
        if (consecutive_send_successes >= SEND_RECOVER_THRESHOLD) {
            send_interval_packets = SEND_INTERVAL_FAST;
        }
        return true;
    }
}

static void syslog_backlog_push(const char *message)
{
    strncpy(syslog_backlog[syslog_backlog_head], message, SYSLOG_MSG_MAX - 1);
    syslog_backlog[syslog_backlog_head][SYSLOG_MSG_MAX - 1] = '\0';

    if (syslog_backlog_count == SYSLOG_BACKLOG_MAX) {
        syslog_backlog_tail = (syslog_backlog_tail + 1) % SYSLOG_BACKLOG_MAX;
        syslog_backlog_dropped++;
    } else {
        syslog_backlog_count++;
    }

    syslog_backlog_head = (syslog_backlog_head + 1) % SYSLOG_BACKLOG_MAX;
}

static bool syslog_backlog_pop(char *message_out)
{
    if (syslog_backlog_count == 0) {
        return false;
    }

    strncpy(message_out, syslog_backlog[syslog_backlog_tail], SYSLOG_MSG_MAX - 1);
    message_out[SYSLOG_MSG_MAX - 1] = '\0';

    syslog_backlog_tail = (syslog_backlog_tail + 1) % SYSLOG_BACKLOG_MAX;
    syslog_backlog_count--;
    return true;
}

static void flush_syslog_backlog(int sock, struct sockaddr_in *dest_addr)
{
    char backlog_message[512];
    uint32_t flush_budget = SYSLOG_FLUSH_BUDGET;

    while (wifi_connected && flush_budget > 0 && syslog_backlog_pop(backlog_message)) {
        if (!send_syslog_udp(sock, dest_addr, backlog_message)) {
            // If forwarding fails again after reconnect, put it back and stop flushing.
            syslog_backlog_push(backlog_message);
            break;
        }
        flush_budget--;
    }

    if (syslog_backlog_dropped > 0 && wifi_connected) {
        ESP_LOGW(TAG2, "Syslog backlog dropped %lu messages while offline", syslog_backlog_dropped);
        syslog_backlog_dropped = 0;
    }
}

// Listen for the collector's UDP broadcast beacon and learn its IP automatically.
// This removes the need to hard-code the collector IP when changing locations.
static void collector_discovery_task(void *arg)
{
    (void)arg;
#if ENABLE_AUTO_DISCOVERY
    int dsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (dsock < 0) {
        ESP_LOGE(TAG, "Discovery socket create failed: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int reuse = 1;
    setsockopt(dsock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htons(DISCOVERY_PORT);
    if (bind(dsock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        ESP_LOGE(TAG, "Discovery bind failed: errno %d", errno);
        close(dsock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Collector discovery listening on UDP :%d (magic '%s')", DISCOVERY_PORT, DISCOVERY_MAGIC);

    char buf[128];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    const size_t magic_len = strlen(DISCOVERY_MAGIC);

    while (1) {
        int n = recvfrom(dsock, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&src, &src_len);
        if (n <= 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        buf[n] = '\0';
        if (strncmp(buf, DISCOVERY_MAGIC, magic_len) != 0) {
            continue;
        }

        uint32_t new_ip = src.sin_addr.s_addr;
        uint16_t new_port = SYSLOG_PORT;
        char *p = strstr(buf, "log=");
        if (p) {
            int parsed = atoi(p + 4);
            if (parsed > 0 && parsed < 65536) new_port = (uint16_t)parsed;
        }

        if (!collector_discovered || collector_ip_be != new_ip || collector_log_port != new_port) {
            collector_ip_be = new_ip;
            collector_log_port = new_port;
            collector_discovered = true;
            ESP_LOGI(TAG, "Discovered collector at %s:%u", inet_ntoa(src.sin_addr), new_port);
        }
    }
#else
    ESP_LOGI(TAG, "Auto-discovery disabled; using static collector %s", COLLECTOR_FALLBACK_IP);
    vTaskDelete(NULL);
#endif
}

// WiFi scanning task
void wifi_scan_task(){
    // init WiFi for scanning
    wifi_scan_config_t scan_config = {
        .ssid = 0,
        .bssid = 0,
        .channel = 0,
        .show_hidden = true
    };

    ESP_LOGI(TAG, "Starting WiFi scan...");
    // start WiFi scan (True = block until scan done)
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));

    // get the scanning AP number
    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    wifi_ap_record_t *ap_info = malloc(sizeof(wifi_ap_record_t) * ap_num);
    if(ap_info){
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_num, ap_info));
    
        ESP_LOGI(TAG, "Found %d access points:", ap_num);
        for(int i = 0; i < ap_num; i++){
            ESP_LOGI(TAG, "SSID: %-32s, RSSI: %d dBm", ap_info[i].ssid, ap_info[i].rssi);
        }
        
        free(ap_info);
    }
}

// This callback will be called for each received WiFi packet in promiscuous mode
void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type){
    // wifi_promiscuous_pkt_t is the structure of the received packet in 
    // promiscuous mode, it contains metadata and payload
    // rx_ctrl is the metadata header, which contains RSSI, channel, timestamp, etc.
    // payload is the actual packet data (802.11), which can be parsed according to the packet type
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    nids_pkt_info_t info;

    // extract common metadata for all packet types
    info.timestamp = pkt->rx_ctrl.timestamp;
    info.ipat = (last_timestamp == 0 || info.timestamp < last_timestamp) ? 0 : (info.timestamp - last_timestamp);
    last_timestamp = info.timestamp;

    info.rssi = pkt->rx_ctrl.rssi;
    info.snr = pkt->rx_ctrl.rssi - pkt->rx_ctrl.noise_floor;
    info.rate = pkt->rx_ctrl.rate;
    info.mcs = pkt->rx_ctrl.mcs;
    info.len = pkt->rx_ctrl.sig_len;

    // extract packet type
    // MGMT: management frame, CTRL: control frame, DATA: data frame, MISC: other type (e.g. MIMO)
    switch(type){
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

    // 802.11 header
    info.seq_ctrl = (info.len >= 24) ? (((pkt->payload[23] << 8) | pkt->payload[22]) >> 4) : 0; // sequence control field is located at offset 22-23 in the 802.11 header for both management and data frames

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
                    strcpy(info.subtype, "AUTH");     // proxy for EAP / auth-based frames
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
                    memcmp(info.dst_mac, sta_mac_bytes, 6) == 0) {
                    info.deauth_targeted = 1;
                }
            }
        } else {
            info.subtype[0] = '\0';
        }
    } else {
        info.subtype[0] = '\0';
    }

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xQueueSendFromISR(pkt_info_queue, &info, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }

    // optional metadata
    // pkt->rx_ctrl.aggregation;
    // pkt->rx_ctrl.stbc;
    // pkt->rx_ctrl.fec_coding;
    // pkt->rx_ctrl.sgi;
    // pkt->rx_ctrl.rate;
    // pkt->rx_ctrl.mcs;
}

void encode_rfc5424(char *buf, size_t size, nids_pkt_info_t *info, uint32_t heap, int64_t uptime_ms) {
    // 1. produce ISO 8601 timestamp with milliseconds precision
    // Note: Currently we are not synchronizing with NTP, so this timestamp is relative to the device startup time
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = gmtime(&tv.tv_sec);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    // 2. package the log message in RFC 5424 format
    // format: <PRI>1 TIMESTAMP HOSTNAME APPNAME PROCID MSGID MSG
    int n = snprintf(buf, size,
        "<%d>1 %s.%03ldZ %s %s - - "
        "[meta@%s subtype=\"%s\" rssi=\"%d\" snr=\"%d\" ipat=\"%lu\" seq=\"%u\" "
        "heap=\"%lu\" minheap=\"%lu\" uptime=\"%lld\" reconn=\"%lu\" qpeak=\"%lu\" "
        "udpfail=\"%lu\" backlog=\"%lu\" dropped=\"%lu\" host_mac=\"%s\" attack=\"%d\" "
        "deauth_tgt=\"%u\" seq_jump=\"%u\" ap_bssid=\"%s\" channel=\"%u\"]",
        SYSLOG_PRI, ts, tv.tv_usec / 1000, HOSTNAME, APP_NAME,
        PEN, info->subtype, info->rssi, info->snr, (unsigned long)info->ipat, info->seq_ctrl,
        (unsigned long)heap, (unsigned long)esp_get_minimum_free_heap_size(),
        (long long)uptime_ms, (unsigned long)wifi_reconnect_count,
        (unsigned long)queue_peak_depth, (unsigned long)udp_send_failure_total,
        (unsigned long)syslog_backlog_count, (unsigned long)syslog_backlog_dropped,
        sta_mac_str, attack_detected ? 1 : 0,
        (unsigned)info->deauth_targeted, (unsigned)info->seq_jump,
        ap_bssid_str, (unsigned)ap_channel);
    if (n < 0 || (size_t)n >= size) {
        ESP_LOGW(TAG2, "syslog truncated (need %d, buf %u) — rebuild/flash with SYSLOG_MSG_MAX>=512",
                 n, (unsigned)size);
    }
}

// --- Simple HTTP server for testing SYN flood impact ---
static esp_err_t get_handler(httpd_req_t *req)
{
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    
    char resp[256];
    snprintf(resp, sizeof(resp),
        "Hello, I am ESP32!\n"
        "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n"
        "SSID: %s\n"
        "Channel: 11\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        WIFI_SSID);
    
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

static void start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 5; // small to make resource exhaustion observable

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri_get = {
            .uri = "/",
            .method = HTTP_GET,
            .handler = get_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(server, &uri_get);
        ESP_LOGI(TAG, "HTTP server started on port 80");
    } else {
        ESP_LOGW(TAG, "Failed to start HTTP server");
    }
}

// Task: print free heap every second for easy syslog collection
static void heap_logger_task(void *arg)
{
    (void)arg;
    while (1) {
        uint32_t free_heap = esp_get_free_heap_size();
        ESP_LOGI("HEAP", "Free heap: %lu bytes", free_heap);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}


// ---- Phase 5: passive detection -> active response (HIPS) ----
// Application-layer mitigation invoked on a high-confidence attack window.
// Rate-limited so a sustained attack does not spam actions.
#define MITIGATION_BLACKLIST_MAX 16
static uint8_t mitigation_blacklist[MITIGATION_BLACKLIST_MAX][6];
static uint32_t mitigation_blacklist_count = 0;
static uint32_t mitigation_events_total = 0;
static int64_t last_mitigation_us = 0;

static bool mac_is_blacklisted(const uint8_t mac[6])
{
    for (uint32_t i = 0; i < mitigation_blacklist_count; i++) {
        if (memcmp(mitigation_blacklist[i], mac, 6) == 0) return true;
    }
    return false;
}

static int64_t last_hips_disconnect_us = 0;

static void nids_mitigate(const nids_pkt_info_t *info)
{
    int64_t now = esp_timer_get_time();
    // Rate-limit mitigation actions to at most once every 2 s.
    if (last_mitigation_us != 0 && (now - last_mitigation_us) < 2000000) {
        return;
    }
    last_mitigation_us = now;
    mitigation_events_total++;

    // 1) Application-layer MAC blacklist (observable via logs / collector).
    //    As a STA the ESP32 cannot drop 802.11 frames in HW, so this is the
    //    enforcement signal for the AP / demo, and a durable local record.
    if (info && !mac_is_blacklisted(info->src_mac) &&
        mitigation_blacklist_count < MITIGATION_BLACKLIST_MAX) {
        memcpy(mitigation_blacklist[mitigation_blacklist_count], info->src_mac, 6);
        mitigation_blacklist_count++;
        ESP_LOGW(TAG2, "[HIPS] Blacklisted attacker %02X:%02X:%02X:%02X:%02X:%02X (total=%lu)",
                 info->src_mac[0], info->src_mac[1], info->src_mac[2],
                 info->src_mac[3], info->src_mac[4], info->src_mac[5],
                 (unsigned long)mitigation_blacklist_count);
    }

    // 2) Exit modem sleep so the RX path stays awake and backlog flushes faster.
    esp_wifi_set_ps(WIFI_PS_NONE);

    // 3) Optional quarantine: brief disconnect to shed poisoned state / flood.
#if HIPS_ENABLE_DISCONNECT
    if (last_hips_disconnect_us == 0 ||
        (now - last_hips_disconnect_us) > (int64_t)HIPS_DISCONNECT_COOLDOWN_MS * 1000) {
        last_hips_disconnect_us = now;
        ESP_LOGW(TAG2, "[HIPS] Quarantine: temporary Wi-Fi disconnect (event #%lu)",
                 (unsigned long)mitigation_events_total);
        wifi_connected = false;
        esp_wifi_disconnect();
        // Reconnect is handled by the existing WIFI_EVENT_STA_DISCONNECTED handler.
    }
#else
    (void)now;
#endif
}

void nids_analysis_task(void* arg){
    nids_pkt_info_t info;
    char syslog_buffer[512];
    uint32_t pkt_count = 0;

    // OLED status counters
    static bool oled_inited = false;
    static int64_t last_oled_update_ms = 0;
    static const int64_t OLED_UPDATE_MIN_INTERVAL_MS = 1500;
    static int8_t last_rssi = 0;
    static uint32_t last_ipat = 0;

    // --- On-device 100 ms window aggregation state (feeds the edge inference model) ---
    const int64_t WINDOW_US = 100000; // 100 ms sliding epoch (matches the dataset methodology)
    int64_t window_start_us = esp_timer_get_time();
    uint32_t w_total = 0, w_beacon = 0, w_deauth = 0, w_probe = 0, w_auth = 0;
    uint32_t w_deauth_tgt = 0, w_seq_jump = 0;
    int32_t w_rssi_sum = 0, w_snr_sum = 0;
    int64_t w_rssi_sq_sum = 0;
    uint32_t w_rssi_cnt = 0;

    // Destination is resolved per send from the auto-discovered collector (see resolve_collector).
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    // Increase UDP send buffer to reduce transient ENOMEM (errno 12) under traffic bursts.
    int sndbuf = DATASET_PROFILE ? (32 * 1024) : (16 * 1024);
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        ESP_LOGW(TAG, "setsockopt SO_SNDBUF failed: errno %d", errno);
    }

    while(1){
        if(xQueueReceive(pkt_info_queue, &info, portMAX_DELAY) == pdTRUE){
            pkt_count++;
            UBaseType_t queue_depth = uxQueueMessagesWaiting(pkt_info_queue);
            if (queue_depth > queue_peak_depth) {
                queue_peak_depth = queue_depth;
            }
            UBaseType_t stack_mark = uxTaskGetStackHighWaterMark(NULL);
            
            // Track latest RSSI and IPAT for OLED display
            last_rssi = info.rssi;
            last_ipat = info.ipat;

            // ---- 100 ms window aggregation feeding the on-device inference model ----
            w_total++;
            w_rssi_sum += info.rssi;
            w_rssi_sq_sum += (int64_t)info.rssi * info.rssi;
            w_snr_sum += info.snr;
            w_rssi_cnt++;
            if (strcmp(info.subtype, "BEACON") == 0)          w_beacon++;
            else if (strcmp(info.subtype, "DEAUTH") == 0)     w_deauth++;
            else if (strcmp(info.subtype, "DISASSOC") == 0)   w_deauth++;
            else if (strncmp(info.subtype, "PROBE", 5) == 0)  w_probe++;
            else if (strcmp(info.subtype, "AUTH") == 0)       w_auth++;
            if (info.deauth_targeted) w_deauth_tgt++;
            if (info.seq_jump)        w_seq_jump++;

            int64_t win_now_us = esp_timer_get_time();
            if ((win_now_us - window_start_us) >= WINDOW_US) {
                double dt = (double)(win_now_us - window_start_us) / 1000000.0;
                if (dt <= 0) dt = 0.1;
                double rssi_mean = w_rssi_cnt ? (double)w_rssi_sum / w_rssi_cnt : 0.0;
                double rssi_var = 0.0;
                if (w_rssi_cnt > 0) {
                    double mean_sq = (double)w_rssi_sq_sum / w_rssi_cnt;
                    rssi_var = mean_sq - rssi_mean * rssi_mean;
                    if (rssi_var < 0) rssi_var = 0;
                }

                nids_window_features_t f;
                f.total_packets  = (double)w_total;
                f.packet_density = (double)w_total / dt;
                f.beacon_packets = (double)w_beacon;
                f.deauth_packets = (double)w_deauth;
                f.deauth_targeted = (double)w_deauth_tgt;
                f.probe_packets  = (double)w_probe;
                f.auth_packets   = (double)w_auth;
                f.seq_jump       = (double)w_seq_jump;
                f.rssi_mean      = rssi_mean;
                f.rssi_var       = rssi_var;
                f.snr_mean       = w_rssi_cnt ? (double)w_snr_sum / w_rssi_cnt : 0.0;
                f.heap           = (double)esp_get_free_heap_size();
                f.minheap        = (double)esp_get_minimum_free_heap_size();
                f.reconn         = (double)wifi_reconnect_count;
                f.qpeak          = (double)queue_peak_depth;
                f.udpfail        = (double)udp_send_failure_total;
                f.backlog        = (double)syslog_backlog_count;

                int64_t t0 = esp_timer_get_time();
                int pred = nids_predict(&f);
                last_inference_us = (uint32_t)(esp_timer_get_time() - t0);
                attack_detected = (pred != 0);

                if (attack_detected) {
                    ESP_LOGW(TAG2, "[INFERENCE] attack window: pkts=%lu deauth=%lu tgt=%lu jump=%lu density=%.0f heap=%.0f (%lu us)",
                             (unsigned long)w_total, (unsigned long)w_deauth,
                             (unsigned long)w_deauth_tgt, (unsigned long)w_seq_jump,
                             f.packet_density, f.heap,
                             (unsigned long)last_inference_us);
#if HIPS_ENABLE
                    nids_mitigate(&info);
#endif
                }

                // reset accumulator for next window
                window_start_us = win_now_us;
                w_total = w_beacon = w_deauth = w_probe = w_auth = 0;
                w_deauth_tgt = w_seq_jump = 0;
                w_rssi_sum = w_snr_sum = 0; w_rssi_sq_sum = 0; w_rssi_cnt = 0;
            }
            
            // Resolve the collector destination for UDP mode (auto-discovered, else static fallback).
            bool udp_ready = false;
            if (SYSlOG_MODE == 1 && sock >= 0) {
                udp_ready = resolve_collector(&dest_addr);
            }

            if (wifi_connected && SYSlOG_MODE == 1 && sock >= 0 && udp_ready) {
                flush_syslog_backlog(sock, &dest_addr);
            }

            // Emit one record every send_interval_packets. When the collector is not
            // known yet (or Wi-Fi is down) records are buffered and flushed on discovery.
            if(pkt_count % send_interval_packets == 0){
                uint32_t free_heap = esp_get_free_heap_size();
                int64_t uptime_ms = esp_timer_get_time() / 1000; // uptime in milliseconds
                stack_mark = uxTaskGetStackHighWaterMark(NULL); // check stack again before sending
                encode_rfc5424(syslog_buffer, sizeof(syslog_buffer), &info, free_heap, uptime_ms);

                if(SYSlOG_MODE == 1){
                    if (wifi_connected && sock >= 0 && udp_ready) {
                        if (!send_syslog_udp(sock, &dest_addr, syslog_buffer)) {
                            syslog_backlog_push(syslog_buffer);
                        }
                    } else {
                        syslog_backlog_push(syslog_buffer); // buffer until Wi-Fi up + collector discovered
                    }
                } else if (SYSlOG_MODE == 2) {
                    send_syslog_serial(syslog_buffer);   // serial path needs no IP at all (location-independent fallback)
                } else {
                    printf("%s\n", syslog_buffer);
                }
            }

            if (!wifi_connected && pkt_count % 500 == 0) {
                ESP_LOGW(TAG2, "WiFi down; buffering syslog (backlog=%lu)", syslog_backlog_count);
            } else if (SYSlOG_MODE == 1 && pkt_count % 500 == 0) {
                if (udp_ready) {
                    ESP_LOGI(TAG2, "Syslog UDP → %s:%u (discovered=%d, backlog=%lu, ok=%lu, fail=%lu)",
                             inet_ntoa(dest_addr.sin_addr),
                             (unsigned)ntohs(dest_addr.sin_port),
                             collector_discovered ? 1 : 0,
                             (unsigned long)syslog_backlog_count,
                             (unsigned long)udp_send_success_total,
                             (unsigned long)udp_send_failure_total);
                } else {
                    ESP_LOGW(TAG2, "Waiting for collector beacon on UDP :%d (backlog=%lu)",
                             DISCOVERY_PORT, syslog_backlog_count);
                }
            }

            if(pkt_count % 100 == 0){ // print info every 100 packets
                uint32_t free_heap = esp_get_free_heap_size();
                ESP_LOGI(TAG2, "Processed %lu packets so far (send interval %lu, heap=%lu, infer=%lu us, attack=%d, hips=%lu)",
                         pkt_count, send_interval_packets, free_heap,
                         (unsigned long)last_inference_us, attack_detected ? 1 : 0,
                         (unsigned long)mitigation_events_total);
                printf("Stack remain: %lu bytes\n", (uint32_t)stack_mark);
                if(!oled_inited){
                    ESP_LOGI(TAG, "Attempting OLED init...");
                    oled_inited = oled_init();
                    if(!oled_inited) {
                        ESP_LOGW(TAG, "OLED init failed");
                    } else {
                        ESP_LOGI(TAG, "OLED init SUCCESS");
                    }
                }
                if(oled_inited && (pkt_count % 200 == 0)){
                    int64_t now_ms = esp_timer_get_time() / 1000;
                    if ((now_ms - last_oled_update_ms) >= OLED_UPDATE_MIN_INTERVAL_MS) {
                        uint8_t current_channel = 11;  // currently fixed at ch 11
                        bool attack_flag = attack_detected; // driven by on-device inference
                        oled_show_stats(wifi_connected, pkt_count, send_interval_packets, free_heap,
                                       last_rssi, last_ipat, stack_mark, current_channel,
                                       wifi_reconnect_count, queue_depth, attack_flag);
                        last_oled_update_ms = now_ms;
                    }
                }
            }
            if(pkt_count >= 100000){ // reset count after 100k packets to avoid overflow
                pkt_count = 0;
            }

            // process the received packet info (e.g. anomaly detection, logging, etc.)
            // for demonstration, we just print the packet info here
            // printf("[%s] IPAT=%lu us, RATE=%d, RSSI=%d dBm, SNR=%d dB, LEN=%lu bytes, HEAP=%lu bytes, STACK=%lu bytes, SRC MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", info.type_str, info.ipat, info.rate, info.rssi, info.snr, info.len, free_heap, (uint32_t)stack_mark, info.src_mac[0], info.src_mac[1], info.src_mac[2], info.src_mac[3], info.src_mac[4], info.src_mac[5]);
        }
    }
}

void app_main(void) {   
    // get the last reset reason
    esp_reset_reason_t reason = esp_reset_reason();
    ESP_LOGI("HIDS", "Last Reset Reason: %d", reason);
#if ENABLE_AUTO_DISCOVERY
    ESP_LOGI(TAG, "Collector: auto-discovery UDP :%d; fallback=%s",
             DISCOVERY_PORT,
             (sizeof(COLLECTOR_FALLBACK_IP) > 1) ? COLLECTOR_FALLBACK_IP : "(none)");
#else
    ESP_LOGI(TAG, "Collector: static %s:%d", COLLECTOR_FALLBACK_IP, SYSLOG_PORT);
#endif

    // init NVS (WiFi driver needs it)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || 
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize I2C for OLED (SDA=21, SCL=22)
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

    // Initialize UART for optional serial syslog output (USB-UART)
    serial_init();

    // init TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

    // create a queue to store packet info for processing
    pkt_info_queue = xQueueCreate(100, sizeof(nids_pkt_info_t));
    xTaskCreate(nids_analysis_task, "nids_analysis_task", 4096, NULL, 5, NULL);

    // start WiFi driver
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    // ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL)); // We don't need to connect to any AP, just sniffing
    // ESP_ERROR_CHECK(esp_wifi_start());
    
    // Setting Wi-Fi ssid and password
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    
    // must be in station mode to enable promiscuous mode, even if we don't actually connect to an AP
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA)); 
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Cache our own STA MAC; used for deauth_targeted + live_state.json.
    {
        uint8_t mac[6] = {0};
        if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
            memcpy(sta_mac_bytes, mac, 6);
            snprintf(sta_mac_str, sizeof(sta_mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            ESP_LOGI(TAG, "STA MAC: %s", sta_mac_str);
        }
    }

    ESP_LOGI(TAG, "Connecting to WiFi...");
    esp_wifi_connect(); // start connecting...
    // Wait for IP_EVENT_STA_GOT_IP via event group instead of fixed delay
    wifi_event_group = xEventGroupCreate();
    if (wifi_event_group == NULL) {
        ESP_LOGW(TAG, "Failed to create wifi event group; falling back to fixed delay");
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_wifi_set_promiscuous(true);
    } else {
        // Wait up to 10 seconds for the IP; if timed out, we still enable promiscuous
        EventBits_t bits = xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(10000));
        if (bits & WIFI_CONNECTED_BIT) {
            ESP_LOGI(TAG, "WiFi got IP (event). Enabling promiscuous mode");
        } else {
            ESP_LOGW(TAG, "Timed out waiting for IP; enabling promiscuous mode anyway");
        }
        esp_wifi_set_promiscuous(true);
    }

    // Start collector auto-discovery listener (learns collector IP from UDP beacon)
#if ENABLE_AUTO_DISCOVERY
    xTaskCreate(collector_discovery_task, "collector_discovery", 3072, NULL, 5, NULL);
#endif

    // Start a simple HTTP server (for SYN flood resource testing)
    start_webserver();

    // Start heap logger task to print free heap every second
    xTaskCreate(heap_logger_task, "heap_logger", 2048, NULL, 5, NULL);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL, // capture all types of packets
    };
    // only capture management frames (e.g. beacon, probe request/response, auth, assoc, etc.)
    // filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; 
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback); // set the callback function to process received packets
    ESP_LOGI(TAG2, "Promiscuous mode enabled. Sniffing packets...");
    
    if(CHANNEL_HOP_MODE == 1){
        ESP_LOGI(TAG2, "Starting channel hopping...");
        uint8_t channel = 1; // start from channel 1
        while(1){
            esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
            ESP_LOGI(TAG2, "Switched to channel %d", channel);
            channel = (channel % 13) + 1; // cycle through channels 1-13
            vTaskDelay(pdMS_TO_TICKS(10000)); // stay on each channel for 10 seconds
        }
    }
    else{
        uint8_t channel = 11; // fixed channel 11
        ESP_LOGI(TAG2, "SET ESP32 at channel %d to collect dataset", channel);
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }

    // ESP_LOGI(TAG, "NIDS Project Starting...");

    // scan WiFi APs in the background
    // while (1) {
    //     wifi_scan_task();

    //     // monitor free heap (Q1)
    //     uint32_t free_heap = esp_get_free_heap_size();
    //     ESP_LOGW("SYS_MONITOR", "Current free heap: %lu bytes", free_heap);
    //     ESP_LOGI(TAG, "Free Heap: %ld bytes", (long)esp_get_free_heap_size());
    //     vTaskDelay(pdMS_TO_TICKS(5000));
    // }
}

// --- UART helper functions for serial syslog ---
// UART configuration: using UART1 (TX=GPIO17, RX=GPIO16) by default.
#define NIDS_UART_PORT UART_NUM_1
#define NIDS_UART_TX_PIN 17
#define NIDS_UART_RX_PIN 16
#define NIDS_UART_BAUD 115200

static void serial_init(void)
{
    const uart_config_t uart_config = {
        .baud_rate = NIDS_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    uart_driver_install(NIDS_UART_PORT, 1024 * 2, 0, 0, NULL, 0);
    uart_param_config(NIDS_UART_PORT, &uart_config);
    uart_set_pin(NIDS_UART_PORT, NIDS_UART_TX_PIN, NIDS_UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
}

static void send_syslog_serial(const char *buffer)
{
    if (buffer == NULL) return;
    size_t len = strlen(buffer);
    // append newline if not present
    bool need_nl = (len == 0 || buffer[len-1] != '\n');
    uart_write_bytes(NIDS_UART_PORT, buffer, len);
    if (need_nl) uart_write_bytes(NIDS_UART_PORT, "\n", 1);
}
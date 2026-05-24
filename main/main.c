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

#define WIFI_SSID "302"
#define WIFI_PASS "88888888"
#define YOUR_CPU_IP_ADDR "10.69.238.170"  // update with your syslog server IP; keep aligned with attack_sync.py (collector on Raspberry Pi or Windows)
#define SYSLOG_PRI 14      // Facility: User(1) * 8 + Severity: Info(6)
#define VERSION "1"
#define HOSTNAME "esp32-node"
#define APP_NAME "NIDS_PROBE"
#define PEN "45917"        // Private Enterprise Number for ESP32 (may apply from IANA later)
#define SYSlOG_MODE 1         // 0: print to console, 1: send via UDP to remote syslog server
#define CHANNEL_HOP_MODE 0 // 0: fixed channel, 1: channel hopping

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
static const uint32_t SEND_INTERVAL_FAST = 10;
static const uint32_t SEND_INTERVAL_SLOW = 20;
static const uint32_t SEND_FAIL_THRESHOLD = 3;
static const uint32_t SEND_RECOVER_THRESHOLD = 10;
static const uint32_t SYSLOG_BACKLOG_MAX = 64;
static const uint32_t SYSLOG_MSG_MAX = 256;

static char syslog_backlog[64][256];
static uint32_t syslog_backlog_head = 0;
static uint32_t syslog_backlog_tail = 0;
static uint32_t syslog_backlog_count = 0;
static uint32_t syslog_backlog_dropped = 0;
static uint32_t queue_peak_depth = 0;

static bool send_syslog_udp(int sock, struct sockaddr_in *dest_addr, const char *buffer);

typedef struct{
    uint32_t timestamp; // packet timestamp
    uint32_t ipat; // inter-packet arrival time in microseconds
    int8_t rssi; // signal strength in dBm
    int8_t snr; // signal-to-noise ratio in dB
    uint8_t rate; // PHY rate encoding
    uint16_t seq_ctrl; // sequence control field from 802.11 header
    uint8_t mcs; // modulation coding scheme for HT/VHT packets
    uint32_t len; // packet length
    uint8_t src_mac[6]; // source MAC address
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

        wifi_connected = true;
        consecutive_send_failures = 0;
        consecutive_send_successes = 0;
        send_interval_packets = SEND_INTERVAL_FAST;
        if (wifi_event_group) {
            xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
    }
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
        return false;
    } else {
        consecutive_send_failures = 0;
        consecutive_send_successes++;
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
    char backlog_message[256];
    uint32_t flush_budget = 4;

    while (wifi_connected && flush_budget > 0 && syslog_backlog_pop(backlog_message)) {
        send_syslog_udp(sock, dest_addr, backlog_message);
        flush_budget--;
    }

    if (syslog_backlog_dropped > 0 && wifi_connected) {
        ESP_LOGW(TAG2, "Syslog backlog dropped %lu messages while offline", syslog_backlog_dropped);
        syslog_backlog_dropped = 0;
    }
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

    memcpy(info.src_mac, pkt->payload + 10, 6); // source MAC address is located at offset 10 in the 802.11 header for both management and data frames

    // 802.11 header
    info.seq_ctrl = (info.len >= 24) ? (((pkt->payload[23] << 8) | pkt->payload[22]) >> 4) : 0; // sequence control field is located at offset 22-23 in the 802.11 header for both management and data frames

    // Parse 802.11 Frame Control to extract subtype when possible
    if (info.len >= 1) {
        uint8_t fc0 = pkt->payload[0];
        uint8_t frame_type = (fc0 >> 2) & 0x3; // 0=Mgmt,1=Ctrl,2=Data
        uint8_t fc_subtype = (fc0 >> 4) & 0xF;
        if (frame_type == 0) { // Management frames
            switch (fc_subtype) {
                case 8:
                    strcpy(info.subtype, "BEACON");
                    break;
                case 4:
                    strcpy(info.subtype, "PROBE_REQ");
                    break;
                case 5:
                    strcpy(info.subtype, "PROBE_RESP");
                    break;
                default:
                    strcpy(info.subtype, "MGMT_OTHER");
                    break;
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
    snprintf(buf, size, 
        "<%d>1 %s.%03ldZ %s %s - - "
        "[meta@%s subtype=\"%s\" rssi=\"%d\" snr=\"%d\" ipat=\"%lu\" seq=\"%u\" heap=\"%lu\" minheap=\"%lu\" uptime=\"%lld\" reconn=\"%lu\" qpeak=\"%lu\" udpfail=\"%lu\" backlog=\"%lu\" dropped=\"%lu\"] "
        "Deauth_Detection_Heartbeat\n",
        SYSLOG_PRI, ts, tv.tv_usec / 1000, HOSTNAME, APP_NAME,
        PEN, info->subtype, info->rssi, info->snr, info->ipat, info->seq_ctrl, heap,
        esp_get_minimum_free_heap_size(), uptime_ms, wifi_reconnect_count, queue_peak_depth,
        udp_send_failure_total, syslog_backlog_count, syslog_backlog_dropped);
}

// --- Simple HTTP server for testing SYN flood impact ---
static esp_err_t get_handler(httpd_req_t *req)
{
    const char *resp = "Hello, I am ESP32!";
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
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


void nids_analysis_task(void* arg){
    nids_pkt_info_t info;
    char syslog_buffer[256];
    uint32_t pkt_count = 0;

    // OLED status counters
    static bool oled_inited = false;
    static int64_t last_oled_update_ms = 0;
    static const int64_t OLED_UPDATE_MIN_INTERVAL_MS = 1500;
    static int8_t last_rssi = 0;
    static uint32_t last_ipat = 0;

    // Initialize persistent UDP socket for syslog transmission if in SYSlOG_MODE
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(YOUR_CPU_IP_ADDR); // update with your syslog server IP
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(514);                        // 514 is the default port for syslog
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    // Increase UDP send buffer to reduce transient ENOMEM (errno 12) under traffic bursts.
    int sndbuf = 16 * 1024;
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
            
            if (wifi_connected && SYSlOG_MODE == 1 && sock >= 0) {
                flush_syslog_backlog(sock, &dest_addr);
            }

            // send only when Wi-Fi is available; otherwise keep a local backlog
            if(wifi_connected && pkt_count % send_interval_packets == 0){
                uint32_t free_heap = esp_get_free_heap_size();
                int64_t uptime_ms = esp_timer_get_time() / 1000; // uptime in milliseconds
                stack_mark = uxTaskGetStackHighWaterMark(NULL); // check stack again before sending
                encode_rfc5424(syslog_buffer, sizeof(syslog_buffer), &info, free_heap, uptime_ms);

                if(SYSlOG_MODE == 1 && sock >= 0){
                    if (!send_syslog_udp(sock, &dest_addr, syslog_buffer)) {
                        syslog_backlog_push(syslog_buffer);
                    }
                } 
                else{
                    printf("%s\n", syslog_buffer);
                }
            } else if (!wifi_connected && pkt_count % 100 == 0) {
                ESP_LOGW(TAG2, "WiFi down; deferring syslog sends (pkt_count=%lu)", pkt_count);
            } else if (!wifi_connected) {
                uint32_t free_heap = esp_get_free_heap_size();
                int64_t uptime_ms = esp_timer_get_time() / 1000;
                encode_rfc5424(syslog_buffer, sizeof(syslog_buffer), &info, free_heap, uptime_ms);
                syslog_backlog_push(syslog_buffer);
            }

            if(pkt_count % 100 == 0){ // print info every 100 packets
                uint32_t free_heap = esp_get_free_heap_size();
                ESP_LOGI(TAG2, "Processed %lu packets so far (send interval %lu, heap=%lu)", pkt_count, send_interval_packets, free_heap);
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
                        bool attack_flag = false;       // TODO: set to true when attack detected
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
    ESP_LOGI(TAG, "Syslog server target: %s:514", YOUR_CPU_IP_ADDR);

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
#include "syslog_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "lwip/sockets.h"
#include "wifi_manager.h"
#include "net_config.h"
#include "nids_calib.h"
#include "nids_gw.h"

static const char *TAG = "SYSLOG";
static const char *TAG2 = "SYSLOG";
static int sock = -1;
static struct sockaddr_in dest_addr;
static bool udp_ready;
static void serial_init(void);
static void send_syslog_serial(const char *buffer);

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
/* Keep this in internal DRAM: 200 × 640 = 128000 bytes.  896-byte rows make
 * the ESP32 dram0_0_seg overflow at link time. */

static const uint32_t SYSLOG_FLUSH_BUDGET = DATASET_PROFILE ? 32 : 16;

static char syslog_backlog[SYSLOG_BACKLOG_MAX][SYSLOG_MSG_MAX];
static uint32_t syslog_backlog_head = 0;
static uint32_t syslog_backlog_tail = 0;
static uint32_t syslog_backlog_count = 0;
static uint32_t syslog_backlog_dropped = 0;
static portMUX_TYPE collector_lock = portMUX_INITIALIZER_UNLOCKED;
static bool collector_discovered;
static uint32_t collector_ip_be; // network byte order
static uint16_t collector_log_port = SYSLOG_PORT;
static bool resolve_collector(struct sockaddr_in *dest_addr)
{
    dest_addr->sin_family = AF_INET;
    portENTER_CRITICAL(&collector_lock);
    bool discovered = collector_discovered;
    if (discovered) {
        dest_addr->sin_addr.s_addr = collector_ip_be;
        dest_addr->sin_port = htons(collector_log_port);
    }
    portEXIT_CRITICAL(&collector_lock);
    if (discovered) {
        return true;
    }
    /* Fallback even while waiting for beacon (non-empty COLLECTOR_FALLBACK_IP). */
    if (COLLECTOR_FALLBACK_IP[0] != '\0') {
        dest_addr->sin_addr.s_addr = inet_addr(COLLECTOR_FALLBACK_IP);
        dest_addr->sin_port = htons(SYSLOG_PORT);
        return (dest_addr->sin_addr.s_addr != INADDR_NONE && dest_addr->sin_addr.s_addr != 0);
    }
    return false;
}

// Function to send syslog message via UDP to a remote server (such as kiwi syslog server)
static bool send_syslog_udp(int sock, struct sockaddr_in *dest_addr, const char *buffer)
{
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
            ESP_LOGW(TAG2, "First syslog UDP TX FAILED → %s:%u errno=%d", inet_ntoa(dest_addr->sin_addr),
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
                     inet_ntoa(dest_addr->sin_addr), (unsigned)ntohs(dest_addr->sin_port),
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
    char backlog_message[SYSLOG_MSG_MAX];
    uint32_t flush_budget = SYSLOG_FLUSH_BUDGET;

    while (wifi_manager_is_connected() && flush_budget > 0 && syslog_backlog_pop(backlog_message)) {
        if (!send_syslog_udp(sock, dest_addr, backlog_message)) {
            // If forwarding fails again after reconnect, put it back and stop flushing.
            syslog_backlog_push(backlog_message);
            break;
        }
        flush_budget--;
    }

    if (syslog_backlog_dropped > 0 && wifi_manager_is_connected()) {
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
            if (parsed > 0 && parsed < 65536)
                new_port = (uint16_t)parsed;
        }

        portENTER_CRITICAL(&collector_lock);
        bool changed = !collector_discovered || collector_ip_be != new_ip || collector_log_port != new_port;
        if (changed) {
            collector_ip_be = new_ip;
            collector_log_port = new_port;
            collector_discovered = true;
        }
        portEXIT_CRITICAL(&collector_lock);
        if (changed) {
            ESP_LOGI(TAG, "Discovered collector at %s:%u", inet_ntoa(src.sin_addr), new_port);
        }
    }
#else
    ESP_LOGI(TAG, "Auto-discovery disabled; using static collector %s", COLLECTOR_FALLBACK_IP);
    vTaskDelete(NULL);
#endif
}

void syslog_encode(char *buf, size_t size, const nids_pkt_info_t *info, const nids_report_state_t *state,
                   uint32_t heap, int64_t uptime_ms, const nids_window_report_t *window)
{
    // 1. produce ISO 8601 timestamp with milliseconds precision
    // Note: Currently we are not synchronizing with NTP, so this timestamp is relative to the device startup
    // time
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = gmtime(&tv.tv_sec);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    // 2. package the log message in RFC 5424 format
    // win_pkts / win_dens / win_{deauth,probe,beacon,auth,bssid,twin,rogue}:
    // on-device 100 ms tumbling-window counters. Subtype win_* align offline
    // aggregate with the board; CSV row subtype counts are thinned.
    // win_bssid = unique addr3 (cap 8). win_twin = unique BSSIDs advertising
    // our SSID that are not the associated AP. win_rogue = lab MAC 02:13:37:00:00:01.
    // win_{mgmt,data,ctrl,bytes,len_*} are frame-composition sidecars (not model.h).
    int n = snprintf(
        buf, size,
        "<%d>1 %s.%03ldZ %s %s - - "
        "[meta@%s subtype=\"%s\" rssi=\"%d\" snr=\"%d\" ipat=\"%lu\" seq=\"%u\" "
        "heap=\"%lu\" minheap=\"%lu\" uptime=\"%lld\" reconn=\"%lu\" qpeak=\"%lu\" "
        "udpfail=\"%lu\" backlog=\"%lu\" dropped=\"%lu\" host_mac=\"%s\" attack=\"%d\" "
        "deauth_tgt=\"%u\" seq_jump=\"%u\" ap_bssid=\"%s\" channel=\"%u\" "
        "win_pkts=\"%lu\" win_dens=\"%.1f\" pred=\"%d\" calib=\"%s\" thr=\"%.1f\" "
        "gw_mac=\"%s\" gw_flip=\"%lu\" "
        "win_deauth=\"%lu\" win_probe=\"%lu\" win_beacon=\"%lu\" win_auth=\"%lu\" "
        "win_bssid=\"%lu\" win_twin=\"%lu\" win_rogue=\"%lu\" "
        "win_mgmt=\"%lu\" win_data=\"%lu\" win_ctrl=\"%lu\" win_bytes=\"%lu\" "
        "win_len_mean=\"%lu\" win_len_max=\"%lu\" "
        "win_mgmt_bytes=\"%lu\" win_data_bytes=\"%lu\"]",
        SYSLOG_PRI, ts, tv.tv_usec / 1000, HOSTNAME, APP_NAME, PEN, info->subtype, info->rssi, info->snr,
        (unsigned long)info->ipat, info->seq_ctrl, (unsigned long)heap,
        (unsigned long)esp_get_minimum_free_heap_size(), (long long)uptime_ms,
        (unsigned long)wifi_manager_reconnect_count(), (unsigned long)state->queue_peak,
        (unsigned long)udp_send_failure_total, (unsigned long)syslog_backlog_count,
        (unsigned long)syslog_backlog_dropped, wifi_manager_sta_mac_str(), state->attack_detected ? 1 : 0,
        (unsigned)info->deauth_targeted, (unsigned)info->seq_jump, wifi_manager_ap_bssid_str(),
        (unsigned)wifi_manager_ap_channel(), (unsigned long)window->pkts, window->dens,
        (int)state->raw_prediction, nids_calib_state_str(), nids_calib_thr_tot(), nids_gw_mac_str(),
        (unsigned long)nids_gw_flip(), (unsigned long)window->deauth, (unsigned long)window->probe,
        (unsigned long)window->beacon, (unsigned long)window->auth, (unsigned long)window->bssid,
        (unsigned long)window->twin, (unsigned long)window->rogue, (unsigned long)window->mgmt,
        (unsigned long)window->data, (unsigned long)window->ctrl, (unsigned long)window->bytes,
        (unsigned long)window->len_mean, (unsigned long)window->len_max, (unsigned long)window->mgmt_bytes,
        (unsigned long)window->data_bytes);
    if (n < 0 || (size_t)n >= size) {
        ESP_LOGW(TAG2, "syslog truncated (need %d, buf %u) — rebuild/flash with SYSLOG_MSG_MAX>=%u", n,
                 (unsigned)size, (unsigned)SYSLOG_MSG_MAX);
    }
}

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
    if (buffer == NULL)
        return;
    size_t len = strlen(buffer);
    // append newline if not present
    bool need_nl = (len == 0 || buffer[len - 1] != '\n');
    uart_write_bytes(NIDS_UART_PORT, buffer, len);
    if (need_nl)
        uart_write_bytes(NIDS_UART_PORT, "\n", 1);
}

void syslog_client_start(void)
{
#if ENABLE_AUTO_DISCOVERY
    ESP_LOGI(TAG, "Collector: auto-discovery UDP :%d; fallback=%s", DISCOVERY_PORT,
             COLLECTOR_FALLBACK_IP[0] ? COLLECTOR_FALLBACK_IP : "(none)");
#else
    ESP_LOGI(TAG, "Collector: static %s:%d", COLLECTOR_FALLBACK_IP, SYSLOG_PORT);
#endif
    if (SYSLOG_MODE == 2)
        serial_init();
    if (SYSLOG_MODE != 1)
        return;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    ESP_ERROR_CHECK(sock >= 0 ? ESP_OK : ESP_FAIL);
    int sndbuf = DATASET_PROFILE ? (32 * 1024) : (16 * 1024);
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        ESP_LOGW(TAG, "setsockopt SO_SNDBUF failed: errno %d", errno);
    }
#if ENABLE_AUTO_DISCOVERY
    ESP_ERROR_CHECK(xTaskCreate(collector_discovery_task, "collector_discovery", 3072, NULL, 5, NULL) ==
                            pdPASS
                        ? ESP_OK
                        : ESP_ERR_NO_MEM);
#endif
}

void syslog_client_on_packet(void)
{
    if (wifi_manager_take_connected_event()) {
        consecutive_send_failures = 0;
        consecutive_send_successes = 0;
        send_interval_packets = SEND_INTERVAL_FAST;
    }
}

void syslog_client_poll(void)
{
    udp_ready = SYSLOG_MODE == 1 && sock >= 0 && resolve_collector(&dest_addr);
    if (wifi_manager_is_connected() && udp_ready)
        flush_syslog_backlog(sock, &dest_addr);
}

void syslog_client_send(const char *message)
{
    if (SYSLOG_MODE == 1) {
        if (wifi_manager_is_connected() && udp_ready) {
            if (!send_syslog_udp(sock, &dest_addr, message))
                syslog_backlog_push(message);
        } else {
            syslog_backlog_push(message);
        }
    } else if (SYSLOG_MODE == 2) {
        send_syslog_serial(message);
    } else {
        printf("%s\n", message);
    }
}

void syslog_client_log_status(uint32_t pkt_count)
{
    portENTER_CRITICAL(&collector_lock);
    bool discovered = collector_discovered;
    portEXIT_CRITICAL(&collector_lock);
    if (!wifi_manager_is_connected() && pkt_count % 500 == 0) {
        ESP_LOGW(TAG2, "WiFi down; buffering syslog (backlog=%lu)", syslog_backlog_count);
    } else if (SYSLOG_MODE == 1 && pkt_count % 500 == 0) {
        if (udp_ready) {
            ESP_LOGI(TAG2, "Syslog UDP → %s:%u (discovered=%d, backlog=%lu, ok=%lu, fail=%lu)",
                     inet_ntoa(dest_addr.sin_addr), (unsigned)ntohs(dest_addr.sin_port), discovered ? 1 : 0,
                     (unsigned long)syslog_backlog_count, (unsigned long)udp_send_success_total,
                     (unsigned long)udp_send_failure_total);
        } else {
            ESP_LOGW(TAG2, "Waiting for collector beacon on UDP :%d (backlog=%lu)", DISCOVERY_PORT,
                     syslog_backlog_count);
        }
    }
}

uint32_t syslog_client_interval(void) { return send_interval_packets; }
uint32_t syslog_client_failures(void) { return udp_send_failure_total; }
uint32_t syslog_client_backlog(void) { return syslog_backlog_count; }

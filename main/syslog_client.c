#include "syslog_client.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "app_config.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "net_config.h"
#include "nids_calib.h"
#include "nids_gw.h"
#include "wifi_manager.h"

static const char *TAG = "NIDS_INIT";
static const char *TAG2 = "NIDS_SNIFFER";

static const uint32_t SEND_INTERVAL_FAST = DATASET_PROFILE ? 50 : 20;
static const uint32_t SEND_INTERVAL_SLOW = DATASET_PROFILE ? 100 : 50;
static const uint32_t SEND_FAIL_THRESHOLD = 3;
static const uint32_t SEND_RECOVER_THRESHOLD = 10;
static const uint32_t SYSLOG_BACKLOG_MAX = SYSLOG_BACKLOG_CAP;
static const uint32_t SYSLOG_FLUSH_BUDGET = DATASET_PROFILE ? 32 : 16;

static uint32_t send_interval_packets = 10;
static uint32_t consecutive_send_failures = 0;
static uint32_t consecutive_send_successes = 0;
static uint32_t udp_send_failure_total = 0;
static uint32_t udp_send_success_total = 0;
static bool syslog_first_tx_logged = false;

static char syslog_backlog[SYSLOG_BACKLOG_CAP][SYSLOG_MSG_MAX];
static uint32_t syslog_backlog_head = 0;
static uint32_t syslog_backlog_tail = 0;
static uint32_t syslog_backlog_count = 0;
static uint32_t syslog_backlog_dropped = 0;

static volatile bool collector_discovered = false;
static volatile uint32_t collector_ip_be = 0;
static volatile uint16_t collector_log_port = SYSLOG_PORT;

static QueueHandle_t uart_mirror_queue = NULL;
static volatile uint32_t uart_mirror_drop_total = 0;

#if SYSlOG_MODE == 2 || (UART_WINDOW_MIRROR_ENABLE && !UART_WINDOW_MIRROR_USE_CONSOLE)
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
    if (buffer == NULL) {
        return;
    }
    size_t len = strlen(buffer);
    bool need_nl = (len == 0 || buffer[len - 1] != '\n');
    uart_write_bytes(NIDS_UART_PORT, buffer, len);
    if (need_nl) {
        uart_write_bytes(NIDS_UART_PORT, "\n", 1);
    }
}
#endif

static void uart_mirror_task(void *arg)
{
    (void)arg;
    char line[SYSLOG_MSG_MAX];
    while (1) {
        if (xQueueReceive(uart_mirror_queue, line, portMAX_DELAY) != pdTRUE) {
            continue;
        }
#if UART_WINDOW_MIRROR_USE_CONSOLE
        printf("[NIDS_WINDOW] %s\n", line);
#elif SYSlOG_MODE == 2 || (UART_WINDOW_MIRROR_ENABLE && !UART_WINDOW_MIRROR_USE_CONSOLE)
        send_syslog_serial(line);
#endif
    }
}

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
        char *port_field = strstr(buf, "log=");
        if (port_field) {
            int parsed = atoi(port_field + 4);
            if (parsed > 0 && parsed < 65536) {
                new_port = (uint16_t)parsed;
            }
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

void syslog_client_prepare(void)
{
#if SYSlOG_MODE == 2 || (UART_WINDOW_MIRROR_ENABLE && !UART_WINDOW_MIRROR_USE_CONSOLE)
    serial_init();
#endif
#if UART_WINDOW_MIRROR_ENABLE
    uart_mirror_queue = xQueueCreate(UART_WINDOW_MIRROR_QUEUE_DEPTH, SYSLOG_MSG_MAX);
    ESP_ERROR_CHECK(uart_mirror_queue ? ESP_OK : ESP_ERR_NO_MEM);
    BaseType_t created = xTaskCreate(uart_mirror_task, "uart_window_mirror", 4096, NULL, 2, NULL);
    ESP_ERROR_CHECK(created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
#endif
}

void syslog_client_start_discovery(void)
{
#if ENABLE_AUTO_DISCOVERY
    xTaskCreate(collector_discovery_task, "collector_discovery", 3072, NULL, 5, NULL);
#endif
}

void syslog_client_on_link_up(void)
{
    consecutive_send_failures = 0;
    consecutive_send_successes = 0;
    send_interval_packets = SEND_INTERVAL_FAST;
}

bool syslog_client_resolve(struct sockaddr_in *dest)
{
    dest->sin_family = AF_INET;
    if (collector_discovered) {
        dest->sin_addr.s_addr = collector_ip_be;
        dest->sin_port = htons(collector_log_port);
        return true;
    }
    if (COLLECTOR_FALLBACK_IP[0] != '\0') {
        dest->sin_addr.s_addr = inet_addr(COLLECTOR_FALLBACK_IP);
        dest->sin_port = htons(SYSLOG_PORT);
        return (dest->sin_addr.s_addr != INADDR_NONE && dest->sin_addr.s_addr != 0);
    }
    return false;
}

bool syslog_client_send(int sock, struct sockaddr_in *dest, const char *message)
{
    int err = sendto(sock, message, strlen(message), 0, (struct sockaddr *)dest, sizeof(*dest));
    if (err < 0 && (errno == ENOMEM || errno == 118)) {
        vTaskDelay(pdMS_TO_TICKS(10));
        err = sendto(sock, message, strlen(message), 0, (struct sockaddr *)dest, sizeof(*dest));
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
                     inet_ntoa(dest->sin_addr), (unsigned)ntohs(dest->sin_port), errno);
        }
        return false;
    }

    udp_send_success_total++;
    consecutive_send_failures = 0;
    consecutive_send_successes++;
    if (!syslog_first_tx_logged) {
        syslog_first_tx_logged = true;
        ESP_LOGI(TAG2, "First syslog UDP TX OK → %s:%u (sendto accepted; Pi must listen :%u)",
                 inet_ntoa(dest->sin_addr),
                 (unsigned)ntohs(dest->sin_port),
                 (unsigned)ntohs(dest->sin_port));
    }
    if (consecutive_send_successes >= SEND_RECOVER_THRESHOLD) {
        send_interval_packets = SEND_INTERVAL_FAST;
    }
    return true;
}

void syslog_client_push(const char *message)
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

void syslog_client_flush(int sock, struct sockaddr_in *dest)
{
    char backlog_message[SYSLOG_MSG_MAX];
    uint32_t flush_budget = SYSLOG_FLUSH_BUDGET;
    while (wifi_manager_is_connected() && flush_budget > 0 && syslog_backlog_pop(backlog_message)) {
        if (!syslog_client_send(sock, dest, backlog_message)) {
            syslog_client_push(backlog_message);
            break;
        }
        flush_budget--;
    }
    if (syslog_backlog_dropped > 0 && wifi_manager_is_connected()) {
        ESP_LOGW(TAG2, "Syslog backlog dropped %lu messages while offline", syslog_backlog_dropped);
        syslog_backlog_dropped = 0;
    }
}

void syslog_client_write_serial(const char *message)
{
#if SYSlOG_MODE == 2 || (UART_WINDOW_MIRROR_ENABLE && !UART_WINDOW_MIRROR_USE_CONSOLE)
    send_syslog_serial(message);
#else
    if (message != NULL) {
        printf("%s\n", message);
    }
#endif
}

void syslog_client_mirror(const char *message)
{
#if UART_WINDOW_MIRROR_ENABLE
    if (message == NULL || uart_mirror_queue == NULL ||
        xQueueSend(uart_mirror_queue, message, 0) != pdTRUE) {
        uart_mirror_drop_total++;
    }
#else
    (void)message;
#endif
}

uint32_t syslog_client_interval(void) { return send_interval_packets; }
uint32_t syslog_client_backlog(void) { return syslog_backlog_count; }
uint32_t syslog_client_dropped(void) { return syslog_backlog_dropped; }
uint32_t syslog_client_failures(void) { return udp_send_failure_total; }
uint32_t syslog_client_successes(void) { return udp_send_success_total; }
uint32_t syslog_client_uart_drops(void) { return uart_mirror_drop_total; }
bool syslog_client_collector_known(void) { return collector_discovered; }

void syslog_encode(char *buf, size_t size, const nids_pkt_info_t *info, uint32_t heap,
                   int64_t uptime_ms, uint32_t queue_peak, int attack, int raw_pred,
                   uint32_t win_pkts, double win_density,
                   uint32_t win_deauth, uint32_t win_probe,
                   uint32_t win_beacon, uint32_t win_auth,
                   uint32_t win_deauth_tgt, uint32_t win_seq_jump,
                   uint32_t win_bssid, uint32_t win_twin, uint32_t win_rogue,
                   uint32_t win_mgmt, uint32_t win_data, uint32_t win_ctrl,
                   uint32_t win_bytes, uint32_t win_len_mean, uint32_t win_len_max,
                   uint32_t win_mgmt_bytes, uint32_t win_data_bytes)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = gmtime(&tv.tv_sec);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    int n = snprintf(buf, size,
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
        SYSLOG_PRI, ts, tv.tv_usec / 1000, HOSTNAME, APP_NAME,
        PEN, info->subtype, info->rssi, info->snr, (unsigned long)info->ipat, info->seq_ctrl,
        (unsigned long)heap, (unsigned long)esp_get_minimum_free_heap_size(),
        (long long)uptime_ms, (unsigned long)wifi_manager_reconnect_count(),
        (unsigned long)queue_peak, (unsigned long)udp_send_failure_total,
        (unsigned long)syslog_backlog_count, (unsigned long)syslog_backlog_dropped,
        wifi_manager_sta_mac_str(), attack,
        (unsigned)win_deauth_tgt, (unsigned)win_seq_jump,
        wifi_manager_ap_bssid_str(), (unsigned)wifi_manager_ap_channel(),
        (unsigned long)win_pkts, win_density,
        raw_pred, nids_calib_state_str(), nids_calib_thr_tot(),
        nids_gw_mac_str(), (unsigned long)nids_gw_flip(),
        (unsigned long)win_deauth, (unsigned long)win_probe,
        (unsigned long)win_beacon, (unsigned long)win_auth,
        (unsigned long)win_bssid, (unsigned long)win_twin, (unsigned long)win_rogue,
        (unsigned long)win_mgmt, (unsigned long)win_data, (unsigned long)win_ctrl,
        (unsigned long)win_bytes, (unsigned long)win_len_mean, (unsigned long)win_len_max,
        (unsigned long)win_mgmt_bytes, (unsigned long)win_data_bytes);
    if (n < 0 || (size_t)n >= size) {
        ESP_LOGW(TAG2, "syslog truncated (need %d, buf %u) — rebuild/flash with SYSLOG_MSG_MAX>=%u",
                 n, (unsigned)size, (unsigned)SYSLOG_MSG_MAX);
    }
}

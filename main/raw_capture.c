#include "raw_capture.h"
#include "app_config.h"

#if RAW_CAPTURE_ENABLED

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "raw_capture_protocol.h"
#include "wifi_manager.h"

#if !CONFIG_IDF_TARGET_ESP32
#error "Raw capture v1 metadata is implemented for the original ESP32 only"
#endif
_Static_assert(RAW_CAPTURE_SNAPLEN > 0 && RAW_CAPTURE_SNAPLEN <= 4095, "ESP32 snaplen range");
_Static_assert(RAW_CAPTURE_POOL_SLOTS > 1 && RAW_CAPTURE_POOL_SLOTS <= 255, "pool index range");
_Static_assert(RAW_CAPTURE_STATUS_MS >= portTICK_PERIOD_MS, "status interval must span a tick");

typedef struct {
    uint64_t device_us;
    uint16_t flags;
    raw_packet_meta_t meta;
    uint8_t rx_ctrl[sizeof(wifi_pkt_rx_ctrl_t)];
    uint8_t payload[RAW_CAPTURE_SNAPLEN];
} capture_slot_t;

typedef struct {
    uint64_t device_us;
    raw_status_t body;
} status_sample_t;

typedef struct {
    uint32_t callbacks, enqueued, drop_pool, invalid, unavailable, truncated;
    uint32_t tx_fail, status_drop, packets_sent;
    uint16_t queue_peak;
} capture_counters_t;

static capture_slot_t s_pool[RAW_CAPTURE_POOL_SLOTS];
static QueueHandle_t s_free_queue, s_ready_queue, s_status_queue;
static capture_counters_t s_counts;
static portMUX_TYPE s_count_lock = portMUX_INITIALIZER_UNLOCKED;
static uint64_t s_boot_id;
static uint32_t s_stream_seq;
static uint32_t s_filter_mask;
static bool s_started;
// Only the serial task uses these buffers; never put a full frame on its stack.
static uint8_t s_decoded[4352];
static uint8_t s_encoded[4400];
_Static_assert(sizeof(raw_wire_header_t) + sizeof(raw_packet_meta_t) +
               sizeof(wifi_pkt_rx_ctrl_t) + RAW_CAPTURE_SNAPLEN + 4 <= sizeof(s_decoded),
               "maximum packet must fit the encoding buffer");

static int discard_log(const char *format, va_list args)
{
    (void)format;
    (void)args;
    return 0;
}

void raw_capture_prepare_console(void)
{
    esp_log_level_set("*", ESP_LOG_NONE);
    esp_log_set_vprintf(discard_log);
}

static void capture_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    // Wi-Fi driver task context (NOT ISR). No allocation, parsing, heap query or UART here.
    const uint64_t now = (uint64_t)esp_timer_get_time();
    portENTER_CRITICAL(&s_count_lock);
    uint32_t packet_seq = s_counts.callbacks++;
    portEXIT_CRITICAL(&s_count_lock);
    if (buf == NULL || type < WIFI_PKT_MGMT || type > WIFI_PKT_MISC) {
        portENTER_CRITICAL(&s_count_lock);
        s_counts.invalid++;
        portEXIT_CRITICAL(&s_count_lock);
        return;
    }

    uint8_t index;
    if (xQueueReceive(s_free_queue, &index, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_count_lock);
        s_counts.drop_pool++;
        portEXIT_CRITICAL(&s_count_lock);
        return;
    }
    const wifi_promiscuous_pkt_t *packet = buf;
    const wifi_pkt_rx_ctrl_t *rx = &packet->rx_ctrl;
    capture_slot_t *slot = &s_pool[index];
    slot->device_us = now;
    slot->flags = 0;
    uint16_t caplen = rx->sig_len;
    // MISC/MIMO reports metadata/length ONLY. Never dereference its payload.
    if (type == WIFI_PKT_MISC) {
        caplen = 0;
        slot->flags |= RAW_FLAG_UNAVAILABLE;
    } else if (caplen > RAW_CAPTURE_SNAPLEN) {
        caplen = RAW_CAPTURE_SNAPLEN;
        slot->flags |= RAW_FLAG_TRUNCATED;
    }
    slot->meta = (raw_packet_meta_t){
        .packet_seq = packet_seq, .rx_timestamp_us32 = rx->timestamp,
        .original_len = rx->sig_len, .captured_len = caplen,
        .rssi = rx->rssi, .noise_floor = rx->noise_floor, .pkt_type = type,
        .channel = rx->channel, .secondary_channel = rx->secondary_channel,
        .rate = rx->rate, .sig_mode = rx->sig_mode, .mcs = rx->mcs, .cwb = rx->cwb,
        .smoothing = rx->smoothing, .not_sounding = rx->not_sounding,
        .aggregation = rx->aggregation, .stbc = rx->stbc, .fec_coding = rx->fec_coding,
        .sgi = rx->sgi, .ampdu_cnt = rx->ampdu_cnt, .ant = rx->ant, .rx_state = rx->rx_state,
        .rx_ctrl_len = sizeof(*rx),
    };
    // Own the data before returning: the driver's pointer is no longer valid afterwards.
    memcpy(slot->rx_ctrl, rx, sizeof(*rx));
    if (caplen != 0) {
        memcpy(slot->payload, packet->payload, caplen);
    }
    // A free slot guarantees room in the ready queue (same capacity).
    const uint16_t flags = slot->flags;
    BaseType_t queued = xQueueSend(s_ready_queue, &index, 0);
    UBaseType_t depth = uxQueueMessagesWaiting(s_ready_queue);
    portENTER_CRITICAL(&s_count_lock);
    if (queued == pdTRUE) {
        s_counts.enqueued++;
        s_counts.unavailable += (flags & RAW_FLAG_UNAVAILABLE) != 0;
        s_counts.truncated += (flags & RAW_FLAG_TRUNCATED) != 0;
        if (depth > s_counts.queue_peak) s_counts.queue_peak = depth;
    } else {
        s_counts.drop_pool++;
    }
    portEXIT_CRITICAL(&s_count_lock);
    if (queued != pdTRUE) {
        xQueueSend(s_free_queue, &index, 0);
    }
}

static void status_task(void *arg)
{
    (void)arg;
    TickType_t last_wake = xTaskGetTickCount();
    uint32_t sample_seq = 0;
    for (;;) {
        status_sample_t sample = {.device_us = (uint64_t)esp_timer_get_time()};
        raw_status_t *body = &sample.body;
        body->sample_seq = sample_seq++;
        body->free_heap = esp_get_free_heap_size();
        body->min_free_heap = esp_get_minimum_free_heap_size();
        body->largest_free_internal = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        body->free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        body->reconnect_count = wifi_manager_reconnect_count();
        body->connected = wifi_manager_is_connected();
        uint8_t primary = 0;
        wifi_second_chan_t secondary;
        if (esp_wifi_get_channel(&primary, &secondary) == ESP_OK) body->primary_channel = primary;
        body->queue_depth = uxQueueMessagesWaiting(s_ready_queue);
        body->pool_free = uxQueueMessagesWaiting(s_free_queue);
        portENTER_CRITICAL(&s_count_lock);
        capture_counters_t counts = s_counts;
        portEXIT_CRITICAL(&s_count_lock);
        body->callback_count = counts.callbacks;
        body->enqueued_count = counts.enqueued;
        body->drop_pool_count = counts.drop_pool;
        body->invalid_count = counts.invalid;
        body->payload_unavailable_count = counts.unavailable;
        body->truncated_count = counts.truncated;
        body->tx_fail_count = counts.tx_fail;
        body->status_drop_count = counts.status_drop;
        body->packets_sent = counts.packets_sent;
        body->queue_peak = counts.queue_peak;
        if (xQueueSend(s_status_queue, &sample, 0) != pdTRUE) {
            portENTER_CRITICAL(&s_count_lock);
            s_counts.status_drop++;
            portEXIT_CRITICAL(&s_count_lock);
        }
        xTaskDelayUntil(&last_wake, pdMS_TO_TICKS(RAW_CAPTURE_STATUS_MS));
    }
}

// Body must already be in s_decoded after the header. Only serial_task calls this.
static bool send_record(uint8_t kind, uint16_t flags, uint64_t device_us, size_t body_len)
{
    raw_wire_header_t header = {
        .magic = {'N', 'I', 'D', 'R'}, .version = RAW_WIRE_VERSION, .kind = kind,
        .flags = flags, .body_len = body_len, .boot_id = s_boot_id,
        .stream_seq = s_stream_seq++, .device_us = device_us,
    };
    size_t len = sizeof(header) + body_len;
    if (len + 4 > sizeof(s_decoded)) {
        portENTER_CRITICAL(&s_count_lock);
        s_counts.tx_fail++;
        portEXIT_CRITICAL(&s_count_lock);
        return false;
    }
    memcpy(s_decoded, &header, sizeof(header));
    uint32_t crc = raw_crc32(s_decoded, len);
    memcpy(s_decoded + len, &crc, sizeof(crc));
    // Leading delimiter isolates any preceding ROM, bootloader or panic text.
    s_encoded[0] = 0;
    size_t encoded_len = raw_cobs_encode(s_decoded, len + 4, s_encoded + 1, sizeof(s_encoded) - 2);
    if (encoded_len == 0) {
        portENTER_CRITICAL(&s_count_lock);
        s_counts.tx_fail++;
        portEXIT_CRITICAL(&s_count_lock);
        return false;
    }
    s_encoded[encoded_len + 1] = 0;
    int sent = uart_write_bytes(UART_NUM_0, s_encoded, encoded_len + 2);
    bool ok = sent == (int)(encoded_len + 2);
    if (!ok) {
        portENTER_CRITICAL(&s_count_lock);
        s_counts.tx_fail++;
        portEXIT_CRITICAL(&s_count_lock);
    }
    return ok;
}

static void send_hello(void)
{
    const esp_app_desc_t *app = esp_app_get_description();
    char hash[65];
    for (size_t i = 0; i < 32; ++i) snprintf(hash + i * 2, 3, "%02x", app->app_elf_sha256[i]);
    // IDF/build version fields are controlled build identifiers, not user input.
    int len = snprintf((char *)s_decoded + sizeof(raw_wire_header_t), 1024,
        "{\"target\":\"esp32\",\"idf_ver\":\"%s\",\"firmware\":\"%s\","
        "\"elf_sha256\":\"%s\",\"mac\":\"%s\",\"baud\":%u,\"snaplen\":%u,"
        "\"pool_slots\":%u,\"status_period_ms\":%u,\"filter_mask\":%lu,"
        "\"role\":\"sta\",\"http_server\":true,\"inference\":false,"
        "\"clock\":\"esp_timer_callback_us\",\"rx_timestamp_bits\":32,"
        "\"rx_ctrl_size\":%u,\"reset_reason\":%d,\"fcs\":\"included_per_idf_sig_len\"}",
        app->idf_ver, app->version, hash, wifi_manager_sta_mac_str(), RAW_CAPTURE_BAUD,
        RAW_CAPTURE_SNAPLEN, RAW_CAPTURE_POOL_SLOTS, RAW_CAPTURE_STATUS_MS,
        (unsigned long)s_filter_mask, (unsigned)sizeof(wifi_pkt_rx_ctrl_t), esp_reset_reason());
    if (len > 0 && len < 1024) send_record(RAW_KIND_HELLO, 0, esp_timer_get_time(), len);
}

static void serial_task(void *arg)
{
    (void)arg;
    int64_t last_hello = -((int64_t)RAW_CAPTURE_HELLO_MS * 1000);
    int64_t last_yield = esp_timer_get_time();
    for (;;) {
        int64_t now = esp_timer_get_time();
        if (now - last_hello >= (int64_t)RAW_CAPTURE_HELLO_MS * 1000) {
            send_hello();
            last_hello = now;
        }
        // Telemetry has its own queue and takes priority over queued frames.
        status_sample_t sample;
        if (xQueueReceive(s_status_queue, &sample, 0) == pdTRUE) {
            memcpy(s_decoded + sizeof(raw_wire_header_t), &sample.body, sizeof(sample.body));
            send_record(RAW_KIND_STATUS, 0, sample.device_us, sizeof(sample.body));
        }
        uint8_t index;
        if (xQueueReceive(s_ready_queue, &index, pdMS_TO_TICKS(10)) != pdTRUE) continue;
        const capture_slot_t *slot = &s_pool[index];
        uint8_t *body = s_decoded + sizeof(raw_wire_header_t);
        memcpy(body, &slot->meta, sizeof(slot->meta));
        body += sizeof(slot->meta);
        memcpy(body, slot->rx_ctrl, sizeof(slot->rx_ctrl));
        body += sizeof(slot->rx_ctrl);
        memcpy(body, slot->payload, slot->meta.captured_len);
        bool ok = send_record(RAW_KIND_PACKET, slot->flags, slot->device_us,
                              sizeof(slot->meta) + sizeof(slot->rx_ctrl) + slot->meta.captured_len);
        if (ok) {
            portENTER_CRITICAL(&s_count_lock);
            s_counts.packets_sent++;
            portEXIT_CRITICAL(&s_count_lock);
        }
        xQueueSend(s_free_queue, &index, 0);
        // Do not impose one RTOS tick per packet (100 Hz would cap us at 100 pps).
        // UART waits normally yield; also leave an idle opportunity under tiny-frame floods.
        now = esp_timer_get_time();
        if (now - last_yield >= 100000) {
            vTaskDelay(1);
            last_yield = esp_timer_get_time();
        }
    }
}

void raw_capture_start(void)
{
    ESP_ERROR_CHECK(s_started ? ESP_ERR_INVALID_STATE : ESP_OK);
    s_started = true;
    // Dedicated UART0, onboard CP2102; no hardware flow control on this board.
    fflush(stdout);
    uart_config_t uart_config = {
        .baud_rate = RAW_CAPTURE_BAUD, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    if (!uart_is_driver_installed(UART_NUM_0)) {
        ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));
    }
    s_free_queue = xQueueCreate(RAW_CAPTURE_POOL_SLOTS, sizeof(uint8_t));
    s_ready_queue = xQueueCreate(RAW_CAPTURE_POOL_SLOTS, sizeof(uint8_t));
    s_status_queue = xQueueCreate(RAW_CAPTURE_STATUS_QUEUE, sizeof(status_sample_t));
    ESP_ERROR_CHECK(s_free_queue && s_ready_queue && s_status_queue ? ESP_OK : ESP_ERR_NO_MEM);
    for (uint8_t i = 0; i < RAW_CAPTURE_POOL_SLOTS; ++i) xQueueSend(s_free_queue, &i, 0);
    s_boot_id = ((uint64_t)esp_random() << 32) | esp_random();
    // Keep the existing STA role. Do not force channel 11 while connected/scanning.
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    s_filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_CTRL |
                    WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MISC;
    wifi_promiscuous_filter_t filter = {.filter_mask = s_filter_mask};
    wifi_promiscuous_filter_t ctrl_filter = {.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter));
    ESP_ERROR_CHECK(xTaskCreate(status_task, "capture_stats", 3072, NULL, 5, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_ERROR_CHECK(xTaskCreate(serial_task, "capture_uart", 4096, NULL, 4, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(capture_callback));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

#endif // RAW_CAPTURE_ENABLED

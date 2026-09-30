#include "system_init.h"

#include "display.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "net_config.h"
#include "nvs_flash.h"

static const char *TAG = "NIDS_INIT";

static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:   return "POWERON";
    case ESP_RST_EXT:       return "EXTERNAL";
    case ESP_RST_SW:        return "SOFTWARE";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "INT_WDT";
    case ESP_RST_TASK_WDT:  return "TASK_WDT";
    case ESP_RST_WDT:       return "WDT";
    case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SDIO:      return "SDIO";
    default:                return "UNKNOWN";
    }
}

static void heap_logger_task(void *arg)
{
    (void)arg;
    while (1) {
        uint32_t free_heap = esp_get_free_heap_size();
        ESP_LOGI("HEAP", "Free heap: %lu bytes", free_heap);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void system_init(void)
{
    esp_reset_reason_t reason = esp_reset_reason();
    ESP_LOGI("HIDS", "Last Reset Reason: %d (%s)", reason, reset_reason_name(reason));
#if ENABLE_AUTO_DISCOVERY
    ESP_LOGI(TAG, "Collector: auto-discovery UDP :%d; fallback=%s",
             DISCOVERY_PORT,
             (sizeof(COLLECTOR_FALLBACK_IP) > 1) ? COLLECTOR_FALLBACK_IP : "(none)");
#else
    ESP_LOGI(TAG, "Collector: static %s:%d", COLLECTOR_FALLBACK_IP, SYSLOG_PORT);
#endif

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    display_prepare_bus();
}

void system_monitor_start(void)
{
    xTaskCreate(heap_logger_task, "heap_logger", 2048, NULL, 5, NULL);
}

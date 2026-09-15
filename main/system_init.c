#include "system_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"

void system_init(void) { ESP_LOGI("HIDS", "Last Reset Reason: %d", esp_reset_reason()); }

void storage_init(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
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

void system_monitor_start(void)
{
    ESP_ERROR_CHECK(xTaskCreate(heap_logger_task, "heap_logger", 2048, NULL, 5, NULL) == pdPASS
                        ? ESP_OK
                        : ESP_ERR_NO_MEM);
}

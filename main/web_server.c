#include "web_server.h"
#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "net_config.h"

static const char *TAG = "WEB";
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
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], WIFI_SSID);

    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

void web_server_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 5; // small to make resource exhaustion observable

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t uri_get = {.uri = "/", .method = HTTP_GET, .handler = get_handler, .user_ctx = NULL};
        httpd_register_uri_handler(server, &uri_get);
        ESP_LOGI(TAG, "HTTP server started on port 80");
    } else {
        ESP_LOGW(TAG, "Failed to start HTTP server");
    }
}

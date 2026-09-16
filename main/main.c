#include "system_init.h"
#include "display.h"
#include "wifi_manager.h"
#include "syslog_client.h"
#include "nids_engine.h"
#include "sniffer.h"
#include "web_server.h"
#include "app_config.h"
#include "raw_capture.h"

// Startup order is intentional: storage -> Wi-Fi -> transport/queue -> capture.
void app_main(void)
{
#if RAW_CAPTURE_ENABLED
    // UART0 belongs exclusively to the binary writer after initialization.
    raw_capture_prepare_console();
    system_init();
    storage_init();
    display_init();
    wifi_manager_init();
    web_server_start();
    raw_capture_start();
#else
    system_init();
    storage_init();
    display_init();
    wifi_manager_init();
    syslog_client_start();
    nids_engine_start();
    web_server_start();
    system_monitor_start();
    sniffer_start(nids_engine_submit);
#endif
}

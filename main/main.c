#include "system_init.h"
#include "display.h"
#include "wifi_manager.h"
#include "syslog_client.h"
#include "nids_engine.h"
#include "sniffer.h"
#include "web_server.h"

// Startup order is intentional: storage -> Wi-Fi -> transport/queue -> capture.
void app_main(void)
{
    system_init();
    storage_init();
    display_init();
    wifi_manager_init();
    syslog_client_start();
    nids_engine_start();
    web_server_start();
    system_monitor_start();
    sniffer_start(nids_engine_submit);
}

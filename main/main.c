#include "http_status.h"
#include "nids_engine.h"
#include "sniffer.h"
#include "syslog_client.h"
#include "system_init.h"
#include "wifi_manager.h"

/* Startup only. Packet parsing, the 100 ms tree, syslog, and the OLED live
 * in their own modules. The classmate refactor's raw-capture mode is not
 * part of this path: inference and UDP syslog stay on. */
void app_main(void)
{
    system_init();
    syslog_client_prepare();
    sniffer_prepare();
    wifi_manager_prepare();
    nids_engine_start();
    wifi_manager_start();
    syslog_client_start_discovery();
    http_status_start();
    system_monitor_start();
    sniffer_start();
}

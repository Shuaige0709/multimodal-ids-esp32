idf_component_register(
    SRCS "main.c" "system_init.c" "display.c" "wifi_manager.c"
         "sniffer.c" "nids_engine.c" "syslog_client.c" "web_server.c"
         "mitigation.c" "nids_gw.c" "oled.c" "nids_calib.c"
         "raw_capture.c" "raw_capture_protocol.c"
    INCLUDE_DIRS ".")

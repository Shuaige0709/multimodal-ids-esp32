#include "nids_engine.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "display.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mitigation.h"
#include "model.h"
#include "net_config.h"
#include "nids_calib.h"
#include "nids_gw.h"
#include "nids_types.h"
#include "sniffer.h"
#include "syslog_client.h"
#include "wifi_manager.h"

static const char *TAG = "NIDS_INIT";
static const char *TAG2 = "NIDS_SNIFFER";

#define NIDS_WIN_BSSID_CAP 8
#define NIDS_WIN_TWIN_CAP 4
static const uint8_t k_lab_rogue_bssid[6] = {0x02, 0x13, 0x37, 0x00, 0x00, 0x01};

static uint8_t s_win_bssids[NIDS_WIN_BSSID_CAP][6];
static uint8_t s_win_bssid_n;
static uint8_t s_win_twins[NIDS_WIN_TWIN_CAP][6];
static uint8_t s_win_twin_n;
static uint8_t s_win_rogue;

static volatile bool attack_detected = false;
static volatile int last_raw_pred = 0;
static volatile uint32_t last_inference_us = 0;
static uint32_t queue_peak_depth = 0;

static int mac_is_zero(const uint8_t *mac)
{
    return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}

static void win_bssid_reset(void)
{
    s_win_bssid_n = 0;
    s_win_twin_n = 0;
    s_win_rogue = 0;
    memset(s_win_bssids, 0, sizeof(s_win_bssids));
    memset(s_win_twins, 0, sizeof(s_win_twins));
}

static void win_bssid_note(const uint8_t *mac)
{
    if (!mac || mac_is_zero(mac)) {
        return;
    }
    for (uint8_t i = 0; i < s_win_bssid_n; i++) {
        if (memcmp(s_win_bssids[i], mac, 6) == 0) {
            return;
        }
    }
    if (s_win_bssid_n < NIDS_WIN_BSSID_CAP) {
        memcpy(s_win_bssids[s_win_bssid_n], mac, 6);
        s_win_bssid_n++;
    }
}

static void win_twin_note(const uint8_t *mac)
{
    if (!mac || mac_is_zero(mac)) {
        return;
    }
    for (uint8_t i = 0; i < s_win_twin_n; i++) {
        if (memcmp(s_win_twins[i], mac, 6) == 0) {
            return;
        }
    }
    if (s_win_twin_n < NIDS_WIN_TWIN_CAP) {
        memcpy(s_win_twins[s_win_twin_n], mac, 6);
        s_win_twin_n++;
    }
}

static void win_identity_note(const nids_pkt_info_t *info)
{
    if (!info) {
        return;
    }
    if (memcmp(info->bssid, k_lab_rogue_bssid, 6) == 0) {
        s_win_rogue = 1;
    }
    if (info->ssid_ours && !mac_is_zero(wifi_manager_ap_bssid()) &&
        memcmp(info->bssid, wifi_manager_ap_bssid(), 6) != 0) {
        win_twin_note(info->bssid);
    }
}

static void nids_analysis_task(void *arg)
{
    (void)arg;
    nids_pkt_info_t info;
    char syslog_buffer[SYSLOG_MSG_MAX];
    uint32_t pkt_count = 0;
    int64_t last_attack_log_us = 0;
    int64_t last_transport_log_us = 0;
    int64_t last_status_log_us = 0;

    const int64_t WINDOW_US = 100000;
    int64_t window_start_us = esp_timer_get_time();
    uint32_t w_total = 0, w_beacon = 0, w_deauth = 0, w_probe = 0, w_auth = 0;
    uint32_t w_mgmt = 0, w_data = 0, w_ctrl = 0;
    uint32_t w_bytes = 0, w_mgmt_bytes = 0, w_data_bytes = 0;
    uint32_t w_len_max = 0;
    uint64_t w_len_sum = 0;
    uint32_t w_deauth_tgt = 0, w_seq_jump = 0;
    win_bssid_reset();
    int32_t w_rssi_sum = 0, w_snr_sum = 0;
    int64_t w_rssi_sq_sum = 0;
    uint32_t w_rssi_cnt = 0;

#if NIDS_CALIB_ENABLE
    nids_calib_reset();
#endif

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int sndbuf = DATASET_PROFILE ? (32 * 1024) : (16 * 1024);
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        ESP_LOGW(TAG, "setsockopt SO_SNDBUF failed: errno %d", errno);
    }

    while (1) {
        if (xQueueReceive(sniffer_queue(), &info, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        pkt_count++;
        UBaseType_t queue_depth = uxQueueMessagesWaiting(sniffer_queue());
        if (queue_depth > queue_peak_depth) {
            queue_peak_depth = queue_depth;
        }
        UBaseType_t stack_mark = uxTaskGetStackHighWaterMark(NULL);
        display_note_rssi(info.rssi);

        w_total++;
        win_bssid_note(info.bssid);
        win_identity_note(&info);
        if (strcmp(info.type_str, "MGMT") == 0) {
            w_mgmt++;
            w_mgmt_bytes += info.len;
        } else if (strcmp(info.type_str, "DATA") == 0) {
            w_data++;
            w_data_bytes += info.len;
        } else if (strcmp(info.type_str, "CTRL") == 0) {
            w_ctrl++;
        }
        w_bytes += info.len;
        w_len_sum += info.len;
        if (info.len > w_len_max) {
            w_len_max = info.len;
        }
        w_rssi_sum += info.rssi;
        w_rssi_sq_sum += (int64_t)info.rssi * info.rssi;
        w_snr_sum += info.snr;
        w_rssi_cnt++;
        if (strcmp(info.subtype, "BEACON") == 0) w_beacon++;
        else if (strcmp(info.subtype, "DEAUTH") == 0) w_deauth++;
        else if (strcmp(info.subtype, "DISASSOC") == 0) w_deauth++;
        else if (strncmp(info.subtype, "PROBE", 5) == 0) w_probe++;
        else if (strcmp(info.subtype, "AUTH") == 0) w_auth++;
        if (info.deauth_targeted) w_deauth_tgt++;
        if (info.seq_jump) w_seq_jump++;

        int64_t win_now_us = esp_timer_get_time();
        uint32_t closed_win_pkts = 0;
        double closed_win_density = 0.0;
        uint32_t closed_win_deauth = 0, closed_win_probe = 0;
        uint32_t closed_win_beacon = 0, closed_win_auth = 0;
        uint32_t closed_win_deauth_tgt = 0, closed_win_seq_jump = 0;
        uint32_t closed_win_bssid = 0, closed_win_twin = 0, closed_win_rogue = 0;
        uint32_t closed_win_mgmt = 0, closed_win_data = 0, closed_win_ctrl = 0;
        uint32_t closed_win_bytes = 0, closed_win_len_mean = 0, closed_win_len_max = 0;
        uint32_t closed_win_mgmt_bytes = 0, closed_win_data_bytes = 0;
        bool just_closed_window = false;
        if ((win_now_us - window_start_us) >= WINDOW_US) {
            double dt = (double)(win_now_us - window_start_us) / 1000000.0;
            if (dt <= 0) dt = 0.1;
            closed_win_pkts = w_total;
            closed_win_density = (double)w_total / dt;
            closed_win_deauth = w_deauth;
            closed_win_probe = w_probe;
            closed_win_beacon = w_beacon;
            closed_win_auth = w_auth;
            closed_win_deauth_tgt = w_deauth_tgt;
            closed_win_seq_jump = w_seq_jump;
            closed_win_bssid = s_win_bssid_n;
            closed_win_twin = s_win_twin_n;
            closed_win_rogue = s_win_rogue;
            closed_win_mgmt = w_mgmt;
            closed_win_data = w_data;
            closed_win_ctrl = w_ctrl;
            closed_win_bytes = w_bytes;
            closed_win_len_max = w_len_max;
            closed_win_len_mean = w_total ? (uint32_t)((w_len_sum + w_total / 2) / w_total) : 0;
            closed_win_mgmt_bytes = w_mgmt_bytes;
            closed_win_data_bytes = w_data_bytes;
            just_closed_window = true;

            double rssi_mean = w_rssi_cnt ? (double)w_rssi_sum / w_rssi_cnt : 0.0;
            double rssi_var = 0.0;
            if (w_rssi_cnt > 0) {
                double mean_sq = (double)w_rssi_sq_sum / w_rssi_cnt;
                rssi_var = mean_sq - rssi_mean * rssi_mean;
                if (rssi_var < 0) rssi_var = 0;
            }

            nids_window_features_t features;
            features.total_packets = (double)w_total;
            features.packet_density = closed_win_density;
            features.beacon_packets = (double)w_beacon;
            features.deauth_packets = (double)w_deauth;
            features.deauth_targeted = (double)w_deauth_tgt;
            features.probe_packets = (double)w_probe;
            features.auth_packets = (double)w_auth;
            features.seq_jump = (double)w_seq_jump;
            features.rssi_mean = rssi_mean;
            features.rssi_var = rssi_var;
            features.snr_mean = w_rssi_cnt ? (double)w_snr_sum / w_rssi_cnt : 0.0;
            features.heap = (double)esp_get_free_heap_size();
            features.minheap = (double)esp_get_minimum_free_heap_size();
            features.reconn = (double)wifi_manager_reconnect_count();
            features.qpeak = (double)queue_peak_depth;
            features.udpfail = (double)syslog_client_failures();
            features.backlog = (double)syslog_client_backlog();

            int64_t t0 = esp_timer_get_time();
            int pred = nids_predict(&features);
            last_raw_pred = pred;
            last_inference_us = (uint32_t)(esp_timer_get_time() - t0);
            bool was_attack_detected = attack_detected;
#if NIDS_CALIB_ENABLE
            attack_detected = nids_calib_on_window(&features, pred);
#else
            attack_detected = (pred != 0);
#endif
            display_note_window(pred, attack_detected ? 1 : 0, attack_detected,
                                closed_win_pkts, closed_win_deauth, closed_win_deauth_tgt,
                                closed_win_auth, closed_win_twin, closed_win_rogue);

            int64_t attack_log_now_us = esp_timer_get_time();
            if (attack_detected &&
                (!was_attack_detected || last_attack_log_us == 0 ||
                 (attack_log_now_us - last_attack_log_us) >= 500000)) {
                last_attack_log_us = attack_log_now_us;
                ESP_LOGW(TAG2,
                         "[INFERENCE] attack window: pred=%d calib=%s thr=%.1f pkts=%lu deauth=%lu tgt=%lu jump=%lu density=%.0f heap=%.0f (%lu us)",
                         pred,
#if NIDS_CALIB_ENABLE
                         nids_calib_state() == NIDS_CALIB_ARMED ? "ARMED" : "CALIB",
                         nids_calib_thr_tot(),
#else
                         "OFF", 0.0,
#endif
                         (unsigned long)w_total, (unsigned long)w_deauth,
                         (unsigned long)w_deauth_tgt, (unsigned long)w_seq_jump,
                         features.packet_density, features.heap,
                         (unsigned long)last_inference_us);
#if HIPS_ENABLE
                mitigation_on_attack(&info);
#endif
            }

#if UART_WINDOW_MIRROR_ENABLE
            syslog_encode(syslog_buffer, sizeof(syslog_buffer), &info,
                          (uint32_t)features.heap, win_now_us / 1000, queue_peak_depth,
                          attack_detected ? 1 : 0, last_raw_pred,
                          closed_win_pkts, closed_win_density,
                          closed_win_deauth, closed_win_probe,
                          closed_win_beacon, closed_win_auth,
                          closed_win_deauth_tgt, closed_win_seq_jump,
                          closed_win_bssid, closed_win_twin, closed_win_rogue,
                          closed_win_mgmt, closed_win_data, closed_win_ctrl,
                          closed_win_bytes, closed_win_len_mean, closed_win_len_max,
                          closed_win_mgmt_bytes, closed_win_data_bytes);
            syslog_client_mirror(syslog_buffer);
#endif

            window_start_us = win_now_us;
            w_total = w_beacon = w_deauth = w_probe = w_auth = 0;
            w_mgmt = w_data = w_ctrl = 0;
            w_bytes = w_mgmt_bytes = w_data_bytes = 0;
            w_len_max = 0;
            w_len_sum = 0;
            w_deauth_tgt = w_seq_jump = 0;
            w_rssi_sum = w_snr_sum = 0;
            w_rssi_sq_sum = 0;
            w_rssi_cnt = 0;
            win_bssid_reset();
        }

        bool udp_ready = false;
        if (SYSlOG_MODE == 1 && sock >= 0) {
            udp_ready = syslog_client_resolve(&dest_addr);
        }
        if (wifi_manager_is_connected() && SYSlOG_MODE == 1 && sock >= 0 && udp_ready) {
            syslog_client_flush(sock, &dest_addr);
        }

        if (pkt_count % syslog_client_interval() == 0) {
            uint32_t free_heap = esp_get_free_heap_size();
            int64_t uptime_ms = esp_timer_get_time() / 1000;
            stack_mark = uxTaskGetStackHighWaterMark(NULL);
            uint32_t report_pkts;
            double report_dens;
            uint32_t report_deauth, report_probe, report_beacon, report_auth;
            uint32_t report_deauth_tgt, report_seq_jump;
            uint32_t report_bssid, report_twin, report_rogue;
            uint32_t report_mgmt, report_data, report_ctrl;
            uint32_t report_bytes, report_len_mean, report_len_max;
            uint32_t report_mgmt_bytes, report_data_bytes;
            if (just_closed_window) {
                report_pkts = closed_win_pkts;
                report_dens = closed_win_density;
                report_deauth = closed_win_deauth;
                report_probe = closed_win_probe;
                report_beacon = closed_win_beacon;
                report_auth = closed_win_auth;
                report_deauth_tgt = closed_win_deauth_tgt;
                report_seq_jump = closed_win_seq_jump;
                report_bssid = closed_win_bssid;
                report_twin = closed_win_twin;
                report_rogue = closed_win_rogue;
                report_mgmt = closed_win_mgmt;
                report_data = closed_win_data;
                report_ctrl = closed_win_ctrl;
                report_bytes = closed_win_bytes;
                report_len_mean = closed_win_len_mean;
                report_len_max = closed_win_len_max;
                report_mgmt_bytes = closed_win_mgmt_bytes;
                report_data_bytes = closed_win_data_bytes;
            } else {
                int64_t elapsed_us = esp_timer_get_time() - window_start_us;
                if (elapsed_us < 1000) {
                    elapsed_us = 1000;
                }
                report_pkts = w_total;
                report_dens = (double)w_total / ((double)elapsed_us / 1000000.0);
                report_deauth = w_deauth;
                report_probe = w_probe;
                report_beacon = w_beacon;
                report_auth = w_auth;
                report_deauth_tgt = w_deauth_tgt;
                report_seq_jump = w_seq_jump;
                report_bssid = s_win_bssid_n;
                report_twin = s_win_twin_n;
                report_rogue = s_win_rogue;
                report_mgmt = w_mgmt;
                report_data = w_data;
                report_ctrl = w_ctrl;
                report_bytes = w_bytes;
                report_len_max = w_len_max;
                report_len_mean = w_total ? (uint32_t)((w_len_sum + w_total / 2) / w_total) : 0;
                report_mgmt_bytes = w_mgmt_bytes;
                report_data_bytes = w_data_bytes;
            }
            nids_gw_poll();
            syslog_encode(syslog_buffer, sizeof(syslog_buffer), &info, free_heap, uptime_ms,
                          queue_peak_depth, attack_detected ? 1 : 0, last_raw_pred,
                          report_pkts, report_dens,
                          report_deauth, report_probe, report_beacon, report_auth,
                          report_deauth_tgt, report_seq_jump,
                          report_bssid, report_twin, report_rogue,
                          report_mgmt, report_data, report_ctrl,
                          report_bytes, report_len_mean, report_len_max,
                          report_mgmt_bytes, report_data_bytes);
            if (SYSlOG_MODE == 1) {
                if (wifi_manager_is_connected() && sock >= 0 && udp_ready) {
                    if (!syslog_client_send(sock, &dest_addr, syslog_buffer)) {
                        syslog_client_push(syslog_buffer);
                    }
                } else {
                    syslog_client_push(syslog_buffer);
                }
            } else if (SYSlOG_MODE == 2) {
                syslog_client_write_serial(syslog_buffer);
            } else {
                printf("%s\n", syslog_buffer);
            }
        }

        int64_t status_now_us = esp_timer_get_time();
        if (last_transport_log_us == 0 || status_now_us - last_transport_log_us >= 5000000) {
            last_transport_log_us = status_now_us;
            if (!wifi_manager_is_connected()) {
                ESP_LOGW(TAG2, "WiFi down; buffering syslog (backlog=%lu)", syslog_client_backlog());
            } else if (SYSlOG_MODE == 1) {
                if (udp_ready) {
                    ESP_LOGI(TAG2, "Syslog UDP → %s:%u (discovered=%d, backlog=%lu, ok=%lu, fail=%lu)",
                             inet_ntoa(dest_addr.sin_addr),
                             (unsigned)ntohs(dest_addr.sin_port),
                             syslog_client_collector_known() ? 1 : 0,
                             (unsigned long)syslog_client_backlog(),
                             (unsigned long)syslog_client_successes(),
                             (unsigned long)syslog_client_failures());
                } else {
                    ESP_LOGW(TAG2, "Waiting for collector beacon on UDP :%d (backlog=%lu)",
                             DISCOVERY_PORT, syslog_client_backlog());
                }
            }
        }

        if (last_status_log_us == 0 || status_now_us - last_status_log_us >= 1000000) {
            last_status_log_us = status_now_us;
            uint32_t free_heap = esp_get_free_heap_size();
            ESP_LOGI(TAG2, "Processed %lu packets so far (send interval %lu, heap=%lu, infer=%lu us, attack=%d, hips=%lu, qdrop=%lu, uartdrop=%lu)",
                     pkt_count, syslog_client_interval(), free_heap,
                     (unsigned long)last_inference_us, attack_detected ? 1 : 0,
                     (unsigned long)mitigation_event_count(),
                     (unsigned long)sniffer_drop_count(),
                     (unsigned long)syslog_client_uart_drops());
            printf("Stack remain: %lu bytes\n", (uint32_t)stack_mark);
            display_tick(wifi_manager_is_connected(), udp_ready, wifi_manager_ap_channel(),
                         wifi_manager_reconnect_count(), syslog_client_backlog(),
                         syslog_client_uart_drops());
        }

        if (pkt_count >= 100000) {
            pkt_count = 0;
        }
    }
}

void nids_engine_start(void)
{
    BaseType_t created = xTaskCreate(nids_analysis_task, "nids_analysis_task", 6144, NULL, 5, NULL);
    ESP_ERROR_CHECK(created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
}

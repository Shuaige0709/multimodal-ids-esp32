#include "nids_engine.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "app_config.h"
#include "net_config.h"
#include "model.h"
#include "nids_calib.h"
#include "nids_gw.h"
#include "wifi_manager.h"
#include "syslog_client.h"
#include "display.h"
#include "mitigation.h"

static const char *TAG2 = "NIDS_ENGINE";
static QueueHandle_t pkt_info_queue;
static uint32_t queue_peak_depth;
static bool attack_detected;
static int last_raw_pred;
static uint32_t last_inference_us;

#define NIDS_WIN_BSSID_CAP 8
#define NIDS_WIN_TWIN_CAP 4
/* Matches host/attacks/attack_evil_twin.sh default NIDS_ROGUE_BSSID. Lab smoke only. */
static const uint8_t k_lab_rogue_bssid[6] = {0x02, 0x13, 0x37, 0x00, 0x00, 0x01};

static uint8_t s_win_bssids[NIDS_WIN_BSSID_CAP][6];
static uint8_t s_win_bssid_n;
static uint8_t s_win_twins[NIDS_WIN_TWIN_CAP][6];
static uint8_t s_win_twin_n;
static uint8_t s_win_rogue;

static int mac_is_zero(const uint8_t *m) { return !(m[0] | m[1] | m[2] | m[3] | m[4] | m[5]); }

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

    // --- On-device 100 ms tumbling window (non-overlapping; matches offline bins) ---
    const int64_t WINDOW_US = 100000; // 100 ms
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

    while (1) {
        if (xQueueReceive(pkt_info_queue, &info, portMAX_DELAY) == pdTRUE) {
            syslog_client_on_packet();
            pkt_count++;
            UBaseType_t queue_depth = uxQueueMessagesWaiting(pkt_info_queue);
            if (queue_depth > queue_peak_depth) {
                queue_peak_depth = queue_depth;
            }
            UBaseType_t stack_mark = uxTaskGetStackHighWaterMark(NULL);

            // ---- 100 ms tumbling window aggregation (feeds on-device inference) ----
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
            if (strcmp(info.subtype, "BEACON") == 0)
                w_beacon++;
            else if (strcmp(info.subtype, "DEAUTH") == 0)
                w_deauth++;
            else if (strcmp(info.subtype, "DISASSOC") == 0)
                w_deauth++;
            else if (strncmp(info.subtype, "PROBE", 5) == 0)
                w_probe++;
            else if (strcmp(info.subtype, "AUTH") == 0)
                w_auth++;
            if (info.deauth_targeted)
                w_deauth_tgt++;
            if (info.seq_jump)
                w_seq_jump++;

            int64_t win_now_us = esp_timer_get_time();
            uint32_t closed_win_pkts = 0;
            double closed_win_density = 0.0;
            uint32_t closed_win_deauth = 0, closed_win_probe = 0;
            uint32_t closed_win_beacon = 0, closed_win_auth = 0;
            uint32_t closed_win_bssid = 0, closed_win_twin = 0, closed_win_rogue = 0;
            uint32_t closed_win_mgmt = 0, closed_win_data = 0, closed_win_ctrl = 0;
            uint32_t closed_win_bytes = 0, closed_win_len_mean = 0, closed_win_len_max = 0;
            uint32_t closed_win_mgmt_bytes = 0, closed_win_data_bytes = 0;
            bool just_closed_window = false;
            if ((win_now_us - window_start_us) >= WINDOW_US) {
                double dt = (double)(win_now_us - window_start_us) / 1000000.0;
                if (dt <= 0)
                    dt = 0.1;
                closed_win_pkts = w_total;
                closed_win_density = (double)w_total / dt;
                closed_win_deauth = w_deauth;
                closed_win_probe = w_probe;
                closed_win_beacon = w_beacon;
                closed_win_auth = w_auth;
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
                    if (rssi_var < 0)
                        rssi_var = 0;
                }

                nids_window_features_t f;
                f.total_packets = (double)w_total;
                f.packet_density = closed_win_density;
                f.beacon_packets = (double)w_beacon;
                f.deauth_packets = (double)w_deauth;
                f.deauth_targeted = (double)w_deauth_tgt;
                f.probe_packets = (double)w_probe;
                f.auth_packets = (double)w_auth;
                f.seq_jump = (double)w_seq_jump;
                f.rssi_mean = rssi_mean;
                f.rssi_var = rssi_var;
                f.snr_mean = w_rssi_cnt ? (double)w_snr_sum / w_rssi_cnt : 0.0;
                f.heap = (double)esp_get_free_heap_size();
                f.minheap = (double)esp_get_minimum_free_heap_size();
                f.reconn = (double)wifi_manager_reconnect_count();
                f.qpeak = (double)queue_peak_depth;
                f.udpfail = (double)syslog_client_failures();
                f.backlog = (double)syslog_client_backlog();

                int64_t t0 = esp_timer_get_time();
                int pred = nids_predict(&f);
                last_raw_pred = pred;
                last_inference_us = (uint32_t)(esp_timer_get_time() - t0);
#if NIDS_CALIB_ENABLE
                attack_detected = nids_calib_on_window(&f, pred);
#else
                attack_detected = (pred != 0);
#endif

                if (attack_detected) {
                    ESP_LOGW(TAG2,
                             "[INFERENCE] attack window: pred=%d calib=%s thr=%.1f pkts=%lu deauth=%lu "
                             "tgt=%lu jump=%lu density=%.0f heap=%.0f (%lu us)",
                             pred,
#if NIDS_CALIB_ENABLE
                             nids_calib_state() == NIDS_CALIB_ARMED ? "ARMED" : "CALIB", nids_calib_thr_tot(),
#else
                             "OFF", 0.0,
#endif
                             (unsigned long)w_total, (unsigned long)w_deauth, (unsigned long)w_deauth_tgt,
                             (unsigned long)w_seq_jump, f.packet_density, f.heap,
                             (unsigned long)last_inference_us);
#if HIPS_ENABLE
                    mitigation_on_attack(&info);
#endif
                }

                // reset accumulator for next window
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

            syslog_client_poll();

            // Emit one record every syslog_client_interval(). When the collector is not
            // known yet (or Wi-Fi is down) records are buffered and flushed on discovery.
            if (pkt_count % syslog_client_interval() == 0) {
                uint32_t free_heap = esp_get_free_heap_size();
                int64_t uptime_ms = esp_timer_get_time() / 1000; // uptime in milliseconds
                stack_mark = uxTaskGetStackHighWaterMark(NULL);  // check stack again before sending
                // Prefer just-closed window totals so syslog matches nids_predict inputs.
                nids_window_report_t report;
                if (just_closed_window) {
                    report.pkts = closed_win_pkts;
                    report.dens = closed_win_density;
                    report.deauth = closed_win_deauth;
                    report.probe = closed_win_probe;
                    report.beacon = closed_win_beacon;
                    report.auth = closed_win_auth;
                    report.bssid = closed_win_bssid;
                    report.twin = closed_win_twin;
                    report.rogue = closed_win_rogue;
                    report.mgmt = closed_win_mgmt;
                    report.data = closed_win_data;
                    report.ctrl = closed_win_ctrl;
                    report.bytes = closed_win_bytes;
                    report.len_mean = closed_win_len_mean;
                    report.len_max = closed_win_len_max;
                    report.mgmt_bytes = closed_win_mgmt_bytes;
                    report.data_bytes = closed_win_data_bytes;
                } else {
                    int64_t elapsed_us = esp_timer_get_time() - window_start_us;
                    if (elapsed_us < 1000) {
                        elapsed_us = 1000;
                    }
                    report.pkts = w_total;
                    report.dens = (double)w_total / ((double)elapsed_us / 1000000.0);
                    report.deauth = w_deauth;
                    report.probe = w_probe;
                    report.beacon = w_beacon;
                    report.auth = w_auth;
                    report.bssid = s_win_bssid_n;
                    report.twin = s_win_twin_n;
                    report.rogue = s_win_rogue;
                    report.mgmt = w_mgmt;
                    report.data = w_data;
                    report.ctrl = w_ctrl;
                    report.bytes = w_bytes;
                    report.len_max = w_len_max;
                    report.len_mean = w_total ? (uint32_t)((w_len_sum + w_total / 2) / w_total) : 0;
                    report.mgmt_bytes = w_mgmt_bytes;
                    report.data_bytes = w_data_bytes;
                }
                nids_report_state_t report_state = {
                    .queue_peak = queue_peak_depth,
                    .attack_detected = attack_detected,
                    .raw_prediction = last_raw_pred,
                };
                nids_gw_poll();
                syslog_encode(syslog_buffer, sizeof(syslog_buffer), &info, &report_state, free_heap,
                              uptime_ms, &report);

                syslog_client_send(syslog_buffer);
            }

            syslog_client_log_status(pkt_count);

            if (pkt_count % 100 == 0) { // print info every 100 packets
                uint32_t free_heap = esp_get_free_heap_size();
                ESP_LOGI(TAG2,
                         "Processed %lu packets so far (send interval %lu, heap=%lu, infer=%lu us, "
                         "attack=%d, hips=%lu)",
                         pkt_count, syslog_client_interval(), free_heap, (unsigned long)last_inference_us,
                         attack_detected ? 1 : 0, (unsigned long)mitigation_event_count());
                printf("Stack remain: %lu bytes\n", (uint32_t)stack_mark);
                display_update(pkt_count, syslog_client_interval(), free_heap, info.rssi, info.ipat,
                               stack_mark, queue_depth, attack_detected);
            }
            if (pkt_count >= 100000) { // reset count after 100k packets to avoid overflow
                pkt_count = 0;
            }

            // process the received packet info (e.g. anomaly detection, logging, etc.)
            // for demonstration, we just print the packet info here
            // printf("[%s] IPAT=%lu us, RATE=%d, RSSI=%d dBm, SNR=%d dB, LEN=%lu bytes, HEAP=%lu bytes,
            // STACK=%lu bytes, SRC MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", info.type_str, info.ipat,
            // info.rate, info.rssi, info.snr, info.len, free_heap, (uint32_t)stack_mark, info.src_mac[0],
            // info.src_mac[1], info.src_mac[2], info.src_mac[3], info.src_mac[4], info.src_mac[5]);
        }
    }
}

void nids_engine_start(void)
{
    pkt_info_queue = xQueueCreate(SNIFFER_QUEUE_LENGTH, sizeof(nids_pkt_info_t));
    ESP_ERROR_CHECK(pkt_info_queue ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_ERROR_CHECK(xTaskCreate(nids_analysis_task, "nids_analysis_task", 4096, NULL, 5, NULL) == pdPASS
                        ? ESP_OK
                        : ESP_ERR_NO_MEM);
}

void nids_engine_submit(const nids_pkt_info_t *packet)
{
    // Promiscuous callbacks execute in the Wi-Fi task, not an interrupt.
    (void)xQueueSend(pkt_info_queue, packet, 0);
}

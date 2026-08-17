#include "nids_calib.h"
#include "net_config.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "NIDS_CALIB";

#ifndef NIDS_CALIB_ENABLE
#define NIDS_CALIB_ENABLE 1
#endif
#ifndef NIDS_CALIB_MS
#define NIDS_CALIB_MS 45000
#endif
#ifndef NIDS_CALIB_K
#define NIDS_CALIB_K 2.0f
#endif
#ifndef NIDS_CALIB_STREAK
#define NIDS_CALIB_STREAK 3
#endif
#ifndef NIDS_CALIB_DEAUTH_STREAK
#define NIDS_CALIB_DEAUTH_STREAK 1
#endif
#ifndef NIDS_CALIB_CLEAR_STREAK
#define NIDS_CALIB_CLEAR_STREAK 2
#endif
#ifndef NIDS_CALIB_RING
#define NIDS_CALIB_RING 128
#endif
#ifndef NIDS_CALIB_MIN_SAMPLES
#define NIDS_CALIB_MIN_SAMPLES 32
#endif

static nids_calib_state_t s_state = NIDS_CALIB_DISABLED;
static int64_t s_calib_start_us = 0;
static float s_ring[NIDS_CALIB_RING];
static int s_ring_n = 0;
static int s_ring_i = 0;
static double s_p90 = 0.0;
static double s_thr = 1.0;
static int s_pos_run = 0;
static int s_neg_run = 0;
static int s_latched = 0;
static int s_logged_arm = 0;

static int cmp_float(const void *a, const void *b)
{
    float fa = *(const float *)a;
    float fb = *(const float *)b;
    return (fa > fb) - (fa < fb);
}

static void ring_push(float tot)
{
    s_ring[s_ring_i] = tot;
    s_ring_i = (s_ring_i + 1) % NIDS_CALIB_RING;
    if (s_ring_n < NIDS_CALIB_RING) {
        s_ring_n++;
    }
}

static double compute_p90(void)
{
    if (s_ring_n <= 0) {
        return 0.0;
    }
    float tmp[NIDS_CALIB_RING];
    memcpy(tmp, s_ring, (size_t)s_ring_n * sizeof(float));
    qsort(tmp, (size_t)s_ring_n, sizeof(float), cmp_float);
    int idx = (int)((s_ring_n - 1) * 0.90);
    if (idx < 0) {
        idx = 0;
    }
    if (idx >= s_ring_n) {
        idx = s_ring_n - 1;
    }
    return (double)tmp[idx];
}

static void try_arm(void)
{
    int64_t elapsed_ms = (esp_timer_get_time() - s_calib_start_us) / 1000;
    if (elapsed_ms < (int64_t)NIDS_CALIB_MS) {
        return;
    }
    if (s_ring_n < NIDS_CALIB_MIN_SAMPLES) {
        return;
    }
    s_p90 = compute_p90();
    s_thr = (double)NIDS_CALIB_K * s_p90;
    if (s_thr < 1.0) {
        s_thr = 1.0;
    }
    s_state = NIDS_CALIB_ARMED;
    s_pos_run = 0;
    s_neg_run = 0;
    s_latched = 0;
    if (!s_logged_arm) {
        s_logged_arm = 1;
        ESP_LOGW(TAG,
                 "*** CALIB ARMED *** after %lld ms: idle_samples=%d p90_tot=%.1f thr_tot=%.1f (k=%.2f)",
                 (long long)elapsed_ms, s_ring_n, s_p90, s_thr, (double)NIDS_CALIB_K);
    }
}

void nids_calib_reset(void)
{
#if !NIDS_CALIB_ENABLE
    s_state = NIDS_CALIB_DISABLED;
    s_latched = 0;
    return;
#else
    memset(s_ring, 0, sizeof(s_ring));
    s_ring_n = 0;
    s_ring_i = 0;
    s_p90 = 0.0;
    s_thr = 1.0;
    s_pos_run = 0;
    s_neg_run = 0;
    s_latched = 0;
    s_logged_arm = 0;
    s_calib_start_us = esp_timer_get_time();
    s_state = NIDS_CALIB_CALIBRATING;
    ESP_LOGI(TAG, "CALIBRATING for %d ms (benign background; no scripted attacks)",
             NIDS_CALIB_MS);
#endif
}

static int apply_streak(int candidate, int deauth_path)
{
    if (candidate) {
        s_neg_run = 0;
        s_pos_run++;
        int need = deauth_path ? NIDS_CALIB_DEAUTH_STREAK : NIDS_CALIB_STREAK;
        if (need < 1) {
            need = 1;
        }
        if (s_pos_run >= need) {
            s_latched = 1;
        }
    } else {
        s_pos_run = 0;
        s_neg_run++;
        if (s_neg_run >= NIDS_CALIB_CLEAR_STREAK) {
            s_latched = 0;
        }
    }
    return s_latched;
}

int nids_calib_on_window(const nids_window_features_t *f, int raw_pred)
{
    if (!f) {
        return 0;
    }

#if !NIDS_CALIB_ENABLE
    return raw_pred != 0;
#else
    if (s_state == NIDS_CALIB_DISABLED) {
        return raw_pred != 0;
    }

    const int deauth_path = (f->deauth_packets > 0.5) || (f->deauth_targeted > 0.5);

    if (s_state == NIDS_CALIB_CALIBRATING) {
        if (!deauth_path) {
            ring_push((float)f->total_packets);
        }
        try_arm();
        /* Still calibrating or just armed this window — stay quiet this tick if not armed yet */
        if (s_state == NIDS_CALIB_CALIBRATING) {
            s_latched = 0;
            s_pos_run = 0;
            s_neg_run = 0;
            return 0;
        }
        /* Fall through into ARMED for the same window after arming. */
    }

    /* ARMED */
    int candidate = 0;
    if (deauth_path) {
        candidate = (raw_pred != 0);
    } else if (raw_pred == 0) {
        candidate = 0;
    } else {
        /* Density / other leaf: require relative excess over local IDLE baseline */
        candidate = (f->total_packets > s_thr) ? 1 : 0;
    }

    return apply_streak(candidate, deauth_path);
#endif
}

nids_calib_state_t nids_calib_state(void)
{
    return s_state;
}

const char *nids_calib_state_str(void)
{
#if !NIDS_CALIB_ENABLE
    return "OFF";
#else
    switch (s_state) {
    case NIDS_CALIB_ARMED:
        return "ARMED";
    case NIDS_CALIB_CALIBRATING:
        return "CALIB";
    default:
        return "OFF";
    }
#endif
}

double nids_calib_thr_tot(void)
{
    return s_thr;
}

double nids_calib_p90_tot(void)
{
    return s_p90;
}

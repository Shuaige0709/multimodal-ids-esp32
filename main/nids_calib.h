/**
 * nids_calib.h — On-device IDLE baseline + density post-filter + streak.
 *
 * Wraps nids_predict: calibrate local total_packets p90 during benign boot,
 * then veto density-leaf false alarms unless tot > k*p90. Deauth path bypasses.
 */
#ifndef NIDS_CALIB_H
#define NIDS_CALIB_H

#include "model.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NIDS_CALIB_DISABLED = 0,
    NIDS_CALIB_CALIBRATING = 1,
    NIDS_CALIB_ARMED = 2,
} nids_calib_state_t;

/** Reset state machine and start a new calibration window (call once at sniffer start). */
void nids_calib_reset(void);

/**
 * Post-filter one closed window.
 * @param f         filled window features (same as passed to nids_predict)
 * @param raw_pred  return value of nids_predict (0/1)
 * @return 1 if attack should be reported, else 0
 */
int nids_calib_on_window(const nids_window_features_t *f, int raw_pred);

nids_calib_state_t nids_calib_state(void);
/** "OFF" / "CALIB" / "ARMED" — for syslog. */
const char *nids_calib_state_str(void);
double nids_calib_thr_tot(void);
double nids_calib_p90_tot(void);

#ifdef __cplusplus
}
#endif

#endif /* NIDS_CALIB_H */

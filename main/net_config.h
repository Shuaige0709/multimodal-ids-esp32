/**
 * net_config.h - Single source of truth for all network settings.
 *
 * Change a location? In most cases you now change NOTHING here: the ESP32
 * auto-discovers the collector via a UDP broadcast beacon. Only the Wi-Fi
 * SSID/password need to match the access point you are using.
 */
#ifndef NIDS_NET_CONFIG_H
#define NIDS_NET_CONFIG_H

/* --- Wi-Fi credentials (must match the AP / phone hotspot) --- */
#define WIFI_SSID "302"
#define WIFI_PASS "88888888"

/* --- Collector ports --- */
#define SYSLOG_PORT 1514        /* UDP port the collector listens on for syslog */
#define DISCOVERY_PORT 5005     /* UDP port the ESP32 listens on for collector beacons */
#define DISCOVERY_MAGIC "NIDS_DISCOVERY"

/*
 * Auto-discovery: when enabled the ESP32 waits for the collector's broadcast
 * beacon and learns its IP automatically, so no IP needs to be typed in when
 * changing locations. Until the beacon is heard, syslog is buffered in the
 * local backlog and flushed on discovery.
 */
#define ENABLE_AUTO_DISCOVERY 1

/*
 * Optional static fallback. Used only when auto-discovery is disabled, or as a
 * last resort if no beacon has been heard yet AND this string is non-empty.
 * Leave as "" to rely purely on auto-discovery.
 */
/* Leave "" for auto-discovery. Set only if beacon fails (your collector Wi-Fi IP). */
#define COLLECTOR_FALLBACK_IP ""

/*
 * HIPS (active response). Keep OFF while testing connectivity / collecting
 * a clean baseline — the current on-device tree still false-positives a lot
 * on ambient Wi-Fi (heap-dominated model). Turn on after you retrain.
 */
#define HIPS_ENABLE 0
#define HIPS_ENABLE_DISCONNECT 0
#define HIPS_DISCONNECT_COOLDOWN_MS 10000

/*
 * On-device IDLE baseline calibration (post-filter; does not change model.h).
 * First NIDS_CALIB_MS after analysis start: learn busy-air p90 of total_packets;
 * then require total_packets > k*p90 for non-deauth attack accepts. Deauth bypasses.
 * Assumption: first ~45s is benign background (no scripted attacks); busy RF is OK.
 */
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

#endif /* NIDS_NET_CONFIG_H */

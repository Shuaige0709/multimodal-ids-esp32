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

#endif /* NIDS_NET_CONFIG_H */

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
#define COLLECTOR_FALLBACK_IP ""

/*
 * HIPS (Host-based Intrusion Prevention): when on-device inference flags an
 * attack window, optionally quarantine by briefly disconnecting Wi-Fi.
 * MAC blacklisting always runs; disconnect is opt-in because it interrupts
 * syslog briefly (the backlog buffer covers the gap).
 */
#define HIPS_ENABLE_DISCONNECT 1
#define HIPS_DISCONNECT_COOLDOWN_MS 10000  /* min gap between quarantine actions */

#endif /* NIDS_NET_CONFIG_H */

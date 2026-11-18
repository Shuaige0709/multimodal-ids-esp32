#pragma once
/* Local, explicitly provisioned trust profile. Never learn trust during attack. */
#if __has_include("arp_guard_profile.h")
#include "arp_guard_profile.h"
#endif
#ifndef ARP_GUARD_ENABLE
#define ARP_GUARD_ENABLE 0
#endif
#ifndef ARP_GUARD_GATEWAY_IP
#define ARP_GUARD_GATEWAY_IP ""
#endif
#ifndef ARP_GUARD_GATEWAY_MAC
#define ARP_GUARD_GATEWAY_MAC ""
#endif
#ifndef ARP_GUARD_BSSID
#define ARP_GUARD_BSSID ""
#endif
#ifndef WIFI_TRUSTED_AP_ENABLE
#define WIFI_TRUSTED_AP_ENABLE ARP_GUARD_ENABLE
#endif
#ifndef WIFI_PMF_REQUIRED
#define WIFI_PMF_REQUIRED 0
#endif

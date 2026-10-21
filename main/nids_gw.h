/**
 * nids_gw.h — STA gateway ARP-cache watch (HIDS sidecar, not in model.h).
 *
 * Promiscuous LLC ARP is opaque under WPA2. Instead watch LwIP's neighbor
 * entry for the default gateway: IP stable + MAC change ⇒ spoof edge.
 */
#ifndef NIDS_GW_H
#define NIDS_GW_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void nids_gw_on_got_ip(uint32_t gw_addr);
void nids_gw_on_disconnect(void);
/** Lookup ARP cache; count MAC edges. Call from analysis task (not ISR). */
void nids_gw_poll(void);
uint32_t nids_gw_flip(void);
/** "AA:BB:..." or "-" if unknown. Valid until next poll. */
const char *nids_gw_mac_str(void);
bool nids_gw_mac_copy(uint8_t out[6]);

#ifdef __cplusplus
}
#endif

#endif

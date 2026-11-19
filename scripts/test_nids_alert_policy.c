#include <assert.h>
#include "nids_alert_policy.h"

int main(void)
{
    for (uint8_t source = 0; source < 8; ++source) {
        uint8_t result = nids_alert_policy_apply(source);
        assert((result & (NIDS_M3_RF | NIDS_M3_ARP)) ==
               (source & (NIDS_M3_RF | NIDS_M3_ARP)));
        assert((result & NIDS_M3_BEACON) ==
               (NIDS_BEACON_ALERT_ENABLE ? (source & NIDS_M3_BEACON) : 0));
    }
    return 0;
}

#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Budget counts attempts, including driver errors. Never runs an ARP flood. */
typedef struct {
    unsigned attempts, remaining, failures;
    uint64_t next_send, next_burst;
} garp_policy_t;

static inline bool garp_due(garp_policy_t *p, bool eligible, bool failed, uint64_t now)
{
    if (!eligible || !failed) {
        p->failures = p->remaining = 0;
        return false;
    }
    if (p->failures < 2) p->failures++;
    if (p->failures < 2 || p->attempts >= 12) return false;
    if (!p->remaining) {
        if (now < p->next_burst) return false;
        p->remaining = 3;
        p->next_burst = now + 30000000ULL;
    }
    if (now < p->next_send) return false;
    p->remaining--;
    p->attempts++;
    p->next_send = now + 1000000ULL;
    return true;
}

#include <assert.h>
#include "../main/garp_policy.h"
int main(void) {
    garp_policy_t p = {0};
    assert(!garp_due(&p, false, true, 0));
    assert(!garp_due(&p, true, true, 0));
    assert(garp_due(&p, true, true, 1000000));
    assert(!garp_due(&p, true, true, 1500000));
    assert(garp_due(&p, true, true, 2000000));
    assert(garp_due(&p, true, true, 3000000));
    assert(!garp_due(&p, true, true, 30000000));
    assert(garp_due(&p, true, true, 31000000));
    assert(!garp_due(&p, true, false, 32000000));
    assert(p.remaining == 0);
    assert(!garp_due(&p, true, true, 33000000));
    assert(!garp_due(&p, true, true, 34000000));
    for (uint64_t t = 61000000; t < 300000000; t += 1000000)
        garp_due(&p, true, true, t);
    assert(p.attempts == 12);
    assert(!garp_due(&p, true, true, 999000000));
    garp_due(&p, false, false, 1000000000);
    assert(p.attempts == 12); /* Scope changes cannot replenish the boot budget. */
    return 0;
}

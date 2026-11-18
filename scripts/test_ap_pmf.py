import unittest
from host.attacks.check_ap_pmf import parse_scan

BSSID = '68:02:B8:BB:AF:57'


def block(mac=BSSID, caps='0080'):
    return (f'BSS {mac}(on wlan0)\n\tfreq: 2462\n\tSSID: 302\n'
            '\tRSN:\t * Version: 1\n'
            f'\t\t * Capabilities: 1-PTKSA-RC MFP-capable (0x{caps})\n'
            '\tWPA:\t * Version: 1\n\t\t * Capabilities: (0x0000)\n')


class PmfTests(unittest.TestCase):
    def test_capability_bits_not_friendly_label_determine_policy(self):
        for caps, state in [('0080', 'capable'), ('00c0', 'required'), ('0000', 'not_advertised')]:
            self.assertEqual(parse_scan(block(caps=caps), BSSID)['status'], state)

    def test_exact_bssid_and_case(self):
        text = block(mac='00:11:22:33:44:55', caps='00c0') + block(caps='0000')
        self.assertEqual(parse_scan(text, BSSID.lower())['status'], 'not_advertised')

    def test_missing_target_unknown(self):
        self.assertEqual(parse_scan(block(), '00:11:22:33:44:55')['reason'], 'target_not_found')

    def test_missing_rsn_does_not_consume_wpa_capabilities(self):
        text = f'BSS {BSSID}(on wlan0)\n\tWPA:\t * Version: 1\n\t\t * Capabilities: (0x00c0)\n'
        self.assertEqual(parse_scan(text, BSSID)['status'], 'unknown')

    def test_malformed_and_conflicting_policy_unknown(self):
        self.assertEqual(parse_scan(block(caps='0040'), BSSID)['status'], 'unknown')
        self.assertEqual(parse_scan(block() + block(caps='0000'), BSSID)['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()

import json
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from scripts.demo_dashboard import DashboardState, alarm_types, start_dashboard


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.s = DashboardState(clock=lambda: self.now)
        self.s.transport(True)

    def row(self, **kwargs):
        result = {'attack': '1', 'm3src': '1', 'win_probe': '20', 'uptime': '10000'}
        result.update(kwargs)
        return result

    def test_ground_truth_and_raw_vote_do_not_raise_alarm(self):
        self.s.ingest('ATTACK START DEAUTH')
        self.assertEqual(self.s.snapshot()['total'], 0)
        self.s.ingest('', self.row(attack='0', pred='1'))
        self.assertEqual(self.s.snapshot()['state'], 'monitoring')
        self.assertEqual(self.s.snapshot()['total'], 0)

    def test_all_sources_and_naming_priority(self):
        self.assertEqual(alarm_types(self.row(m3src='7', win_deauth='2')),
                         ['ARP 身分異常', 'Beacon Flood', 'Deauth / Disassoc'])
        self.assertEqual(alarm_types(self.row(win_twin='1')), ['Evil Twin'])
        self.assertEqual(alarm_types(self.row(m3src='4')), ['ARP 身分異常'])

    def test_episode_grouping_and_negative_window_clears_current_alarm(self):
        self.s.ingest('', self.row())
        self.now += .1
        self.s.ingest('', self.row(attack='0'))
        self.assertEqual(self.s.snapshot()['types'], [])
        self.now += .1
        self.s.ingest('', self.row())
        self.assertEqual(self.s.snapshot()['total'], 1)
        self.assertEqual(self.s.snapshot()['events'][0]['windows'], 2)
        self.now += 3
        self.s.ingest('', self.row())
        self.assertEqual(self.s.snapshot()['total'], 2)

    def test_silent_uart_never_stays_live_or_normal(self):
        self.s.ingest('', self.row())
        self.now += 3
        self.assertEqual(self.s.snapshot()['types'], [])
        self.assertEqual(self.s.snapshot()['state'], 'waiting')
        self.now += 3
        self.assertEqual(self.s.snapshot()['state'], 'stale')
        self.s.ingest('I HEAP Free heap: 170000')
        self.assertEqual(self.s.snapshot()['state'], 'waiting')

    def test_wifi_is_independent_of_uart_and_attack_labels(self):
        self.assertEqual(self.s.snapshot()['wifi'], 'unknown')
        self.s.ingest('I Got IP: 192.168.0.10, Netmask: 255.255.255.0')
        self.assertEqual(self.s.snapshot()['wifi'], 'up')
        self.s.ingest('W WiFi disconnected (reason=7); pausing UDP sends')
        self.assertEqual(self.s.snapshot()['wifi'], 'down')
        self.assertEqual(self.s.snapshot()['total'], 0)
        self.s.ingest('', self.row())
        self.assertEqual(self.s.snapshot()['events'][0]['wifi'], 'down')
        self.s.transport(False, 'USB removed')
        self.assertEqual(self.s.snapshot()['state'], 'offline')
        self.s.transport(True)
        self.assertEqual(self.s.snapshot()['wifi'], 'unknown')
        self.assertEqual(self.s.snapshot()['total'], 1)

    def test_board_restart_breaks_episode_and_link_assumptions(self):
        self.s.ingest('', self.row(uptime='100000'))
        self.now += .1
        self.s.ingest('', self.row(uptime='1000'))
        self.assertEqual(self.s.snapshot()['total'], 2)
        self.s.ingest('rst:0x1 (POWERON_RESET)')
        self.assertEqual(self.s.snapshot()['types'], [])
        self.assertEqual(self.s.snapshot()['state'], 'waiting')

    def test_missing_final_prediction_cannot_be_normal(self):
        self.s.ingest('', {'uptime': '100'})
        self.assertEqual(self.s.snapshot()['state'], 'waiting')

    def test_late_attach_link_heartbeat_is_not_an_alarm(self):
        self.s.ingest('I NIDS_SNIFFER: [NIDS_LINK] connected=1 channel=11')
        self.assertEqual(self.s.snapshot()['wifi'], 'up')
        self.assertEqual(self.s.snapshot()['state'], 'waiting')
        self.assertEqual(self.s.snapshot()['total'], 0)
        self.s.ingest('I NIDS_SNIFFER: [NIDS_LINK] connected=0 channel=11')
        self.assertEqual(self.s.snapshot()['wifi'], 'down')
        self.s.transport(False)
        self.s.transport(True)
        self.assertEqual(self.s.snapshot()['wifi'], 'unknown')
        self.s.ingest('I NIDS_SNIFFER: [NIDS_LINK] connected=1 channel=6')
        self.assertEqual(self.s.snapshot()['wifi'], 'up')

    def test_history_is_bounded(self):
        for i in range(120):
            self.now += 3
            self.s.ingest('', self.row())
        self.assertEqual(len(self.s.snapshot()['events']), 100)
        self.assertEqual(self.s.snapshot()['total'], 120)

    def test_disconnect_retry_and_recovery_are_one_measured_episode(self):
        self.s.ingest('[NIDS_LINK] connected=1 channel=11')
        self.now += 1
        self.s.ingest('WiFi disconnected (reason=7); reconnect in 1000 ms')
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'down')
        self.now += 1
        self.s.ingest('[NIDS_RECONNECT] attempt result=ESP_OK')
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'reconnecting')
        self.now += 1
        self.s.ingest('WiFi disconnected (reason=205); reconnect in 2000 ms')
        self.now += 1
        self.s.ingest('[NIDS_RECONNECT] attempt result=ESP_OK')
        self.now += 1
        self.s.ingest('Got IP: 192.168.0.10')
        c = self.s.snapshot()['connection']
        self.assertEqual(c['phase'], 'recovered')
        self.assertEqual(c['total'], 1)
        self.assertEqual(c['outages'][0]['duration'], 4)
        self.assertEqual(c['outages'][0]['attempts'], 2)
        self.now += 1
        self.s.ingest('[NIDS_LINK] connected=1 channel=11')
        self.assertEqual(self.s.snapshot()['connection']['outages'][0]['duration'], 4)
        self.assertEqual(self.s.snapshot()['total'], 0)

    def test_initial_connect_is_not_recovery_or_known_outage(self):
        self.s.ingest('[NIDS_RECONNECT] attempt result=ESP_OK')
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'connecting')
        self.s.ingest('Got IP: 192.168.0.10')
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'up')
        self.assertEqual(self.s.snapshot()['connection']['total'], 0)

    def test_late_attach_down_does_not_claim_full_duration(self):
        self.s.ingest('[NIDS_LINK] connected=0 channel=11')
        self.now += 2
        self.s.ingest('[NIDS_LINK] connected=1 channel=11')
        e = self.s.snapshot()['connection']['outages'][0]
        self.assertFalse(e['start_known'])
        self.assertEqual(e['duration'], 2)

    def test_uart_loss_and_restart_cannot_be_reported_as_recovery(self):
        self.s.ingest('WiFi disconnected (reason=7)')
        self.s.transport(False)
        self.s.transport(True)
        self.s.ingest('Got IP: 192.168.0.10')
        c = self.s.snapshot()['connection']
        self.assertEqual(c['phase'], 'up')
        self.assertEqual(c['outages'][0]['outcome'], 'interrupted')
        self.assertIsNone(c['outages'][0]['duration'])
        self.s.ingest('WiFi disconnected (reason=7)')
        self.s.ingest('rst:0x1 (POWERON_RESET)')
        self.s.ingest('Got IP: 192.168.0.10')
        self.assertEqual(self.s.snapshot()['connection']['outages'][0]['outcome'], 'interrupted')

    def test_unobserved_gap_is_not_measured_recovery(self):
        self.s.ingest('WiFi disconnected (reason=7)')
        self.now += 10
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'unknown')
        self.s.ingest('Got IP: 192.168.0.10')
        self.assertEqual(self.s.snapshot()['connection']['phase'], 'up')
        self.assertEqual(self.s.snapshot()['connection']['outages'][0]['outcome'], 'interrupted')

    def test_http_page_api_and_no_filesystem_exposure(self):
        server = start_dashboard(self.s, '127.0.0.1', 0)
        url = 'http://127.0.0.1:' + str(server.server_port)
        try:
            with urlopen(url + '/') as response:
                self.assertIn('燕子守望', response.read().decode())
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
            with urlopen(url + '/api/status') as response:
                self.assertEqual(json.load(response)['wifi'], 'unknown')
            for asset in ('dashboard.css', 'dashboard.js', 'Geist.woff2', 'favicon.svg',
                          'watch-effects.js', 'shader-engine.js', 'shaders-LICENSE.txt'):
                with urlopen(url + '/assets/' + asset) as response:
                    self.assertGreater(len(response.read()), 0)
            with self.assertRaises(HTTPError):
                urlopen(url + '/../../main/net_config.h')
        finally:
            server.shutdown()
            server.server_close()

    def test_rule_install_is_not_communication_recovery(self):
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'unknown')
        for seq in range(1,4):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=ok sent={seq} received={seq} repair=1')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'reachable')

    def test_failed_then_repaired_and_three_replies_confirms_recovery(self):
        self.s.ingest('[ARP_GUARD] mode=on action=watch repairs=0 err=0')
        for seq in (1,2):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=timeout sent={seq} received=0 repair=0')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'failed')
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        for seq in (3,4):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=ok sent={seq} received={seq-2} repair=1')
            self.assertEqual(self.s.snapshot()['protection']['communication'], 'checking')
        self.s.ingest('[ARP_PROBE] target=192.168.0.1 result=ok sent=5 received=3 repair=1')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'recovered')
        self.now += 6
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'unknown')

    def test_duplicate_reply_does_not_count_as_three_verifications(self):
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        for _ in range(3):
            self.s.ingest('[ARP_PROBE] target=192.168.0.1 result=ok sent=1 received=1 repair=1')
        self.assertEqual(self.s.snapshot()['protection']['success_streak'], 1)

    def test_guard_event_is_separate_from_labels_and_survives_negative_rf(self):
        self.s.ingest('[ARP_GUARD_EVENT] mismatch=1 observed=AA:BB:CC:DD:EE:FF')
        self.s.ingest('', self.row(attack='0'))
        self.assertEqual(self.s.snapshot()['types'], ['ARP 身分異常'])
        self.assertEqual(self.s.snapshot()['total'], 1)
        self.now += 3
        self.assertEqual(self.s.snapshot()['types'], [])

    def test_reset_and_usb_loss_clear_protection_verification(self):
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        self.s.transport(False)
        self.s.transport(True)
        p = self.s.snapshot()['protection']
        self.assertEqual(p['mode'], 'unknown')
        self.assertEqual(p['communication'], 'unknown')
        self.assertGreater(len(p['actions']), 0)

    def test_garp_send_needs_new_replies_and_is_not_itself_recovery(self):
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        for seq in (1, 2):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=timeout sent={seq} received=0 repair=1')
        self.s.ingest('[ARP_GARP] action=sent count=1 budget=12 err=0')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'checking')
        for seq in (3, 4):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=ok sent={seq} received={seq-2} repair=1')
            self.assertEqual(self.s.snapshot()['protection']['communication'], 'checking')
        self.s.ingest('[ARP_PROBE] target=192.168.0.1 result=ok sent=5 received=3 repair=1')
        p = self.s.snapshot()['protection']
        self.assertEqual(p['communication'], 'recovered')
        self.assertEqual(p['garp']['count'], 1)
        self.assertEqual(p['actions'][0]['action'], 'garp_sent')

    def test_wireless_configuration_is_freshness_bound_and_cleared_on_reset(self):
        self.s.ingest('[WIFI_DEFENSE] binding=on pmf=optional bssid=68:02:B8:BB:AF:57 garp=12 budget=12')
        p = self.s.snapshot()['protection']
        self.assertTrue(p['wireless_fresh'])
        self.assertEqual(p['wireless']['pmf'], 'optional')
        self.assertEqual(p['garp']['count'], 12)
        self.now += 6
        self.assertFalse(self.s.snapshot()['protection']['wireless_fresh'])
        self.s.ingest('rst:0x1 (POWERON_RESET)')
        self.assertEqual(self.s.snapshot()['protection']['garp']['count'], 0)

    def test_garp_error_never_confirms_recovery(self):
        self.s.ingest('[ARP_GUARD] mode=on action=locked repairs=1 err=0')
        self.s.ingest('[ARP_GARP] action=error count=12 budget=12 err=-4')
        self.assertNotEqual(self.s.snapshot()['protection']['communication'], 'recovered')
        self.assertEqual(self.s.snapshot()['protection']['actions'][0]['action'], 'garp_error')

    def test_disabled_or_failed_guard_cannot_claim_defense_recovery(self):
        self.s.ingest('[ARP_GUARD] mode=off action=detected repairs=0 err=0')
        for seq in (1,2):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=timeout sent={seq} received=0 repair=0')
        self.s.ingest('[ARP_GUARD] mode=off action=watch repairs=0 err=0')
        for seq in (3,4,5):
            self.s.ingest(f'[ARP_PROBE] target=192.168.0.1 result=ok sent={seq} received={seq-2} repair=0')
        self.assertEqual(self.s.snapshot()['protection']['communication'], 'reachable')


if __name__ == '__main__':
    unittest.main()

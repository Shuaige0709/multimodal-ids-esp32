# Five-minute presentation and two-minute Q&A

Timing assumes five minutes for presentation and live demonstration, followed by two minutes of questions. The PDF contains exactly five slides. The following timing includes time to switch windows and wait for real device behavior; it is a target, not a guaranteed attack or recovery duration.

## Slide 1 — Swallow Watch | 0:00–0:30

“Good afternoon. We present Swallow Watch, a lightweight intrusion detection system running on an ESP32.

Our goal is to show three things: whether an attack is detected, whether the device is affected, and whether a useful response is possible. These are different outcomes, and our system makes each of them visible.”

## Slide 2 — System architecture | 0:30–1:10

“We use two complementary sources. Wireless frame statistics reveal nearby management-frame attacks. Local device state adds gateway-identity changes and connection events.

A compact decision tree and protocol rules run on the ESP32. We do not simply put every device counter into one classifier. Instead, each source handles the threats it can actually observe.

The OLED provides a local alert, while the laptop and phone dashboard display the live decisions and connection state over USB.”

Source: the architecture figure is copied unchanged from `docs/mids_mid_project/report_figures/poster_system_architecture.pdf`, also used in the written report. Automatic ARP repair is a later extension; do not imply the original figure independently evaluates it.

## Slide 3 — Fixed-AP detection results | 1:10–1:50

“Our reported evaluation contains eight attack runs across six scenarios. This figure shows the fraction of attack windows with an alarm, and the time to the first alarm.

For ARP, the detector reports an identity-change event rather than repeating an alarm in every window. In a separate normal recording lasting almost four hours, we observed one false-alarm episode.

These are detection results. They do not mean that every attack was blocked.”

Source: `docs/mids_mid_project/report_figures/board_alarm_windows_and_delay.png`; written-report Table V and the normal-only results. This is the earlier reported dataset, not the later November protection campaign. The plotted alarm fractions are not accuracy, precision, or a blocking rate. Keep that distinction if asked.

## Slide 4 — Live demonstration | 1:50–4:15

Switch to the English **live** dashboard. The Kali terminal was prepared before the talk. A second operator is helpful but not required. Two Enter presses launch the attacks; pressing Enter during an attack stops it early. Do not switch the dashboard to playback.

### First: one-way ARP spoofing

Press Enter at the ARP prompt.

“The attacker is now trying to impersonate the gateway. Please watch the alert, the automatic protection action, and the router-response status.

The ESP32 can repair and lock its trusted gateway entry. The response check tells us whether communication is still available.”

If the expected action is actually visible:

“Here, the gateway is locked and router replies are available.”

If it is not visible, say instead:

“The expected response is not confirmed in this run. We should not call that a successful repair.”

The default ARP tool duration is 25 seconds; start-up and labels add overhead. The script then changes Kali's adapter to monitor mode automatically. While that happens, say:

“ARP is a local-network attack. Next, we will attack the wireless connection itself.”

### Second: targeted deauthentication

Press Enter at the deauthentication prompt.

“This attack attempts to disconnect the ESP32 from its access point. The wireless detector reports the attack, and the connection panel shows whether the device actually disconnects.

Our current AP does not advertise PMF protection, so this demonstration focuses on detection and automatic recovery.”

After the tool stops, point to the actual reconnecting state and outage timer. Only after recovery is confirmed:

“The Wi-Fi connection has returned, and the router is responding again. The dashboard retains the measured outage duration.”

If recovery is not yet confirmed, do not wait indefinitely:

“Recovery is still in progress. The dashboard correctly keeps that outcome unconfirmed.”

Return to slide 5 by approximately 4:15. Do not rerun a failed attack during the five-minute slot. Press Ctrl+C in Kali to stop owned attack processes and restore networking if the session must end early.

## Slide 5 — Takeaways | 4:15–5:00

“Our contribution is an on-device detector with complementary wireless and host observations, plus a clear view of device impact and response.

We evaluated six attack scenarios, demonstrated useful protection in a one-way ARP test, and implemented automatic recovery after wireless disconnection.

There are clear boundaries. Two-way ARP can still affect the return path, and PMF protection has not been validated on this AP. We distinguish these limits from successful detection.

Thank you. We welcome your questions.”

## Short answers for the two-minute Q&A

**Why call it multimodal?**

“The sources observe different things: over-the-air wireless frames and local host/network state. They are complementary. Gateway-identity changes extend ARP coverage; connection logs explain endpoint impact.”

**Did combining features improve accuracy?**

“Generic feature merging did not improve our available comparisons. We therefore use separate, threat-specific decisions rather than claiming that more inputs always improve classification.”

**Can you block all six attacks?**

“No. Six scenarios were evaluated for detection. Successful protection is currently supported for our one-way ARP test. Deauthentication is demonstrated as detection and recovery, not blocking.”

**Does ARP protection work against two-way poisoning?**

“Not reliably in our tests. Locking the ESP32 entry does not control the router's return-path entry. Limited announcements were not enough to maintain communication under the two-way attack.”

**Why not use PMF?**

“The ESP32 supports it, but this AP configuration does not advertise it. We did not treat an unavailable PMF test as a protection success.”

**Is this running on the laptop?**

“Detection and ARP repair run on the ESP32. The laptop reads live USB logs and presents the results. It is not the classifier.”

**Why USB? Do you need a Raspberry Pi?**

“USB keeps observations available when Wi-Fi is attacked. This demonstration does not require a Raspberry Pi.”

**What does the normal false-alarm result mean?**

“We observed one episode during 3 hours and 57 minutes at one AP. It is a measured result for that setting, not a guarantee across all networks.”

**What is the numerical evidence for ARP protection?**

“In the later functional campaign, the one-way ARP interval had 46 router replies and no timeouts with protection, versus 4 replies and 27 timeouts without it. Those are observations from one campaign pair, not a universal success probability.”

Source for the last answer and two-way limits: `docs/demo_acceptance_results_20261118.md` and its companion JSON. That source is separate from the reported detection figure on slide 3.

**Why are you not comparing protection On and Off live?**

“The policy is selected in the firmware build. The live demonstration uses protection On; the Off comparison comes from the completed paired experiment.”

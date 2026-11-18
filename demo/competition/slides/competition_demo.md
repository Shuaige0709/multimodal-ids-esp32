---
marp: true
size: 16:9
paginate: true
theme: default
title: A Lightweight Multimodal IoT Intrusion Detection System on ESP32
author: Yun-Xiang Lin, Yan-Wei Chen, Tzu-Hao Hsu
style: |
  section { font-family: 'Segoe UI', sans-serif; font-size: 26px; line-height: 1.4; color: #1f2328; background: #fff; padding: 45px 65px; }
  h1 { font-size: 36px; line-height: 1.25; color: #224466; }
  h2 { font-size: 30px; margin-bottom: 0.35em; color: #224466; }
  h3 { font-size: 25px; margin: 0.4em 0 0.2em; color: #374151; }
  ul { margin: 0.2em 0; }
  li { margin: 0.15em 0; }
  .architecture { display: block; width: 100%; height: 245px; object-fit: contain; margin: 15px 0 20px; }
  .results { display: block; width: 100%; height: 410px; object-fit: contain; }
  .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 55px; margin: 25px 0; }
  .columns li { margin: 0.55em 0; }
  .note { font-size: 22px; color: #62717c; }
  .authors { margin-top: 45px; font-size: 24px; }
  .affiliation { font-size: 22px; }
---

<!-- _class: lead -->
<!-- _paginate: false -->

# A Lightweight Multimodal IoT<br>Intrusion Detection System on ESP32

<div class="authors">Yun-Xiang Lin · Yan-Wei Chen · Tzu-Hao Hsu</div>

<div class="affiliation">National Sun Yat-sen University</div>

<!--
0:00–0:30. Introduce the project as a team contribution.
“Good afternoon. Our project is a lightweight multimodal intrusion detection system running on an ESP32. We distinguish whether an attack is detected, whether the device is affected, and whether a useful response is possible.”
-->

---

## System architecture

**Wireless observations + local device state**

<img class="architecture" src="assets/system_architecture.svg" />

- A compact decision tree and protocol rules run on the ESP32.
- Gateway identity adds ARP coverage; connection events show device impact.
- OLED and a live USB dashboard make alerts and recovery visible.

<!--
0:30–1:10. Explain the two complementary sources and the three decision paths.
Source: the unchanged architecture figure from docs/mids_mid_project/report_figures/poster_system_architecture.svg. Gateway repair is a later demo extension; the original figure describes detection and telemetry.
-->

---

## Fixed-AP detection results

<img class="results" src="assets/detection_results.png" />

**8 attack runs, 6 scenarios.** One false-alarm episode in 3 h 57 min.

<div class="note">Alarm coverage measures detection during an attack, not successful blocking.</div>

<!--
1:10–1:50. Explain alarmed-window coverage and first-alarm time. ARP is reported as an identity-change event, not a persistent window prediction.
Source: unchanged docs/mids_mid_project/report_figures/board_alarm_windows_and_delay.png and written-report Table V. These are the reported detection runs, distinct from the November protection campaign.
-->

---

## Live demonstration

<div class="columns">
<div>

### ARP spoofing

- Detect gateway impersonation
- Repair and lock the trusted gateway
- Check actual router replies

</div>
<div>

### Deauthentication

- Detect wireless attack traffic
- Observe a real Wi-Fi outage
- Reconnect and measure recovery

</div>
</div>

**Detection, protection, and recovery are separate outcomes.**

<!--
1:50–4:15. Switch to the live English dashboard. Launch each real attack with the prepared Kali terminal; do not use playback. Return to slide 5 by about 4:15, even if a recovery remains unconfirmed.
The first scenario is one-way ARP. The second demonstrates detection and recovery, not prevention of deauthentication. Full operator cues are in ../speaker_notes_en.md.
-->

---

## Takeaways

- **On-device detection:** six tested attack scenarios on a single AP.
- **Complementary sources:** wireless frames reveal attacks; host events add ARP coverage and endpoint context.
- **Visible response:** one-way ARP repair and automatic Wi-Fi recovery.

<div class="note">Two-way ARP remains unresolved. PMF is not enabled in this AP configuration.</div>

<!--
4:15–5:00. Summarize team contributions and distinguish measured detection, targeted protection, and automatic recovery. Q&A follows for two minutes.
Source for protection limits: docs/demo_acceptance_results_20261118.md. Do not present the live demonstration as a new controlled protection-effectiveness experiment.
-->

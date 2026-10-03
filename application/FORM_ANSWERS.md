# COMET 5G Springboard 6 — application answers

Paste each section into the matching Google Form field. Text in **[brackets]** is for you
to fill in or confirm before submitting. Every technical claim below traces to code or a
measured result in this repository.

---

## Name of Founder
**[Founder's full name]**

## Founder's Email ID
abhimanyumalik05@gmail.com **[confirm, or replace with the official company email]**

## Founder's Contact Number
**[+91 …]**

## Name of the Startup / Innovation
YellowSense Technologies — **SenseTrust: Zero-Trust Security for Industrial CPS/IoT**

## CIN copy / DPIIT certificate
**[Upload PDFs]**

---

## Briefly describe your startup/innovation and the problem you are solving.

YellowSense Technologies builds AI-driven security and identity products. Our flagship work is a
contactless fingerprint authentication SDK, built under UIDAI's SITAA programme (Cohort 1,
project SU-C1-2025-02). It captures fingerprints with an ordinary smartphone camera and detects
spoofs such as a finger photo held up on a screen.

SenseTrust applies that work to critical infrastructure. Water plants, substations and
factories still trust whatever arrives on their control network. A sensor reading counts as the
truth because of where it comes from. A command runs because it came from the control room. An
attacker with one stolen device key, or one rogue device on a switch, can feed false readings to
controllers and push the plant into an unsafe state. Existing monitoring tools can tell an
operator that *something is wrong*. They can't say whether to send a technician or an incident
responder.

SenseTrust verifies every reading, command and device-to-device message on its own merits:
- device identity (mutual TLS);
- human identity (fingerprint plus liveness check for critical commands);
- physical plausibility (does the reading agree with plant physics?).

It separates a **broken sensor** from a **lying sensor** and responds to each correctly,
automatically.

## Which COMET 5G Springboard 6 Problem Statement(s) does your solution address?

**Problem Statement 13: Zero-Trust Security for CPS/IoT.** Our working PoC covers all seven
elements of the statement:

- **Device identity:** a plant certificate authority issues each sensor, actuator and console an
  X.509 (ECDSA P-256) identity. Revocation takes effect on the very next request.
- **Authentication:** mutual TLS 1.3 for every device. Operators use contactless fingerprint plus
  a screen-replay liveness check from our UIDAI SITAA SDK.
- **Secure access:** default-deny policy for every request. Operator tokens are short-lived,
  scoped and bound to one console's certificate. Critical commands require a fingerprint check
  less than 5 minutes old, or less than 30 seconds while the plant is under attack.
- **Encryption:** TLS 1.3 in transit. AES-256-GCM for biometric templates and telemetry at rest.
- **Anomaly detection:** physics-based residuals plus IsolationForest, which separate faults
  from attacks.
- **Secure APIs:** signed payloads, nonce, sequence and timestamp replay protection, and rate
  limiting.
- **M2M trust:** a controller checks a peer's identity, signature and live trust score before
  acting on its data. Compromised peers are quarantined automatically.

## Describe your proposed technology/product/solution.

SenseTrust is a zero-trust gateway that sits between field devices, operators and the control
system. Each request goes through eight steps:
1. Identity: certificate check.
2. Integrity: signature check.
3. Freshness: replay check.
4. Behaviour: rate limit and trust score.
5. Policy decision: allow, deny, or ask for a fresh biometric check (step-up).
6. Evidence: denied requests feed the trust score and the detector.
7. Physics check, once per second.
8. Automated response.

**Main idea: telling a fault from an attack.** Plant instruments measure physically linked
quantities. For example, tank level and pressure must agree through hydrostatics, and the level
must change in line with inflow minus outflow. SenseTrust predicts each sensor from the others,
identifies which sensor disagrees, and then reads that sensor's own signal:
- Dropouts, frozen values, noise bursts and out-of-range readings → **fault**: maintenance
  ticket, and the reading is dropped from control loops. The device keeps its identity.
- A healthy-looking signal that contradicts physics, or one with security evidence on its
  channel → **attack**: quarantine, certificate revocation, and the controller switches to a
  physics-consistent estimate of the value.
- Slow, smooth divergence → **ambiguous**: inspection ticket and reduced trust. We say so
  honestly instead of guessing.

**Measured on a simulated water-treatment plant:**
- 0 false alarms in 15 hours of normal operation.
- 324 of 324 injected faults and attacks detected, with the correct sensor identified every time.
- Faults wrongly treated as attacks: 1.1%. Attacks wrongly treated as faults: 0.7%.
- Median time to detect an attack: 10.5 s.
- In a stolen-key false-data attack, a conventional setup overflowed the tank for 110 s.
  SenseTrust detected the attack in 2 s, revoked the device and prevented the overflow.
- Gateway decision time: under 1 ms per request; biometric login under 25 ms.

**Tech stack:** Python, `cryptography`, scikit-learn, Streamlit dashboard, Docker, 36 automated
tests. Designed to work with 5G networks: device identities can be anchored to SIM/eSIM, and
access policy can take the network slice into account.

## Current Technology Readiness Level (TRL)

Select **Proof of Concept**.

If there is a comment field, add: *The zero-trust gateway is a working PoC validated in
simulation (TRL 3–4). The contactless fingerprint engine it uses is a prototype from our UIDAI
SITAA PoC, with an Android app and cloud backends.*

## What is the current stage of validation/pilot/customer adoption?

- **UIDAI SITAA, Cohort 1 (project SU-C1-2025-02).** YellowSense is building the contactless
  fingerprint authentication PoC under UIDAI's SITAA programme. It includes an Android app
  (Register + Authenticate), single-finger and 4-finger slap backends, liveness and
  screen-replay spoof detection, and ISO/IEC 19794-2/-4 template export. Matching accuracy on
  real phone captures is still being improved: our 31-identity test currently measures an EER
  of about 43%, and UIDAI's acceptance target is above 85% accuracy. **[Add any commercial or
  engagement terms you're able to disclose.]**
- **SenseTrust PoC.** It is validated in a physics-based simulation of a water-treatment plant:
  324 injected fault/attack episodes, 15 hours of normal operation, and 7 end-to-end attack
  scenarios. All of it is reproducible from our repository.
- **Not yet field-tested on a live plant.** A pilot site is the main thing we are asking COMET
  to help with.

## What support are you seeking from COMET Foundation apart from funding?

1. **Pilot site and industry connect.** We need a water utility, smart-grid substation or
   factory floor to run SenseTrust in monitoring-only mode on real historian data and calibrate
   it to that site.
2. **5G testbed access.** We want to test SIM/eSIM-anchored device identity and slice-aware
   policy on the IIIT Bangalore / COMET 5G infrastructure.
3. **Technical mentorship.** Specifically on OT/ICS security (IEC 62443 alignment) and on
   hardware root of trust (TPM / secure element, HSM-backed CA).
4. **Technology validation.** An independent red-team assessment of the PoC.
5. **Market access and investor connect.** Introductions to critical-infrastructure operators,
   PSUs and system integrators, and to deep-tech investors.

## Pitch deck
Upload the PDF export of the SenseTrust deck.

---

## Milestones to quote if asked (12 months)

| Months | Milestone |
|---|---|
| 0–3 | Hardware-backed device keys (TPM/secure element); OPC UA + MQTT adapters; IEC 62443 gap analysis |
| 3–6 | Shadow-mode pilot on a live site; site-specific calibration; red-team test |
| 6–9 | Fingerprint engine: on-device pipeline, improved real-capture accuracy toward the UIDAI >85% target |
| 9–12 | 5G identity and slice-aware policy on the COMET testbed; first paid deployment |

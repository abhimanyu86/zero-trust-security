# SenseTrust — Zero-Trust security for industrial CPS/IoT

**YellowSense Technologies** · proof of concept for COMET 5G Springboard 6, Problem Statement 13
(Zero-Trust Security for CPS/IoT: device identity, authentication, secure access, encryption,
anomaly detection, secure APIs, machine-to-machine trust).

Industrial plants still trust whatever arrives on the plant network. SenseTrust checks every
reading, command and device-to-device message on its own merits, with three questions:

1. **Is this device who it says it is?** Mutual TLS 1.3 against a plant CA, with an ECDSA
   signature on every message.
2. **Is this human who they say they are, right now?** Critical commands need a contactless
   fingerprint plus a liveness check. This reuses YellowSense's fingerprint SDK built for the
   UIDAI SITAA programme.
3. **Is what it's saying physically possible?** Sensor readings are checked against plant
   physics. That separates a **broken sensor** (raise a maintenance ticket) from a **lying
   sensor** (quarantine it and revoke its certificate within the same second).

The third check matters most. A stolen device key passes every cryptographic check, so physics
is the only thing left that can catch the lie.

## Results (simulated water-treatment plant, `python -m sensetrust.evaluate`)

| What | Result |
|---|---|
| False alarms during normal operation | **0 in 15 hours** (60 unseen episodes) |
| Injected faults and attacks detected | **324 / 324**, correct sensor isolated in all cases |
| Faults wrongly treated as attacks (needless revocation) | **1.1%** |
| Attacks wrongly treated as faults | **0.7%** |
| Median time to detect: attacks / faults | **10.5 s / 13 s** |
| Stolen-key false-data attack (scenario S2) | tank overflow **110 s → 0 s**, detected in **2 s**, certificate auto-revoked |
| Gateway decision latency, median (laptop CPU; varies by machine) | telemetry and commands **under 1 ms**, biometric login **under 25 ms** |

Full tables are in [`results/EVALUATION.md`](results/EVALUATION.md). **Read the caveats there.**
Slow drift and a patient "stealth ramp" attack can't be told apart from process data alone, so
the system honestly reports them as *ambiguous* (inspection ticket plus reduced trust) instead of
guessing. Biometric figures come from synthetic data. Real-capture accuracy of the fingerprint
engine is an open work item (see below).

## Demo scenarios — `python -m sensetrust.scenarios`

| | Scenario | PS-13 capability | Outcome |
|---|---|---|---|
| S1 | Rogue/cloned device with an attacker-CA certificate | Device identity | denied |
| S2 | Stolen LT-101 key reports the tank 1.2 m low | Anomaly detection, revocation | detected in 2 s, quarantined, pump falls back to physics-consistent level, no overflow |
| S3 | Finger photo held up on a phone screen for a critical command | Authentication | replay detected, login denied; genuine live finger allowed |
| S4 | Captured command and telemetry re-sent, and a delayed message | Secure APIs | nonce / sequence / timestamp rejection |
| S5 | LT-101 transmitter freezes (real fault) | Fault vs attack | maintenance ticket, identity untouched, value dropped from control loop |
| S6 | Operator token stolen and used from another console; privilege escalation | Secure access | denied: token bound to console certificate, scope check |
| S7 | Forged "tank low" message to the pump controller | M2M trust | denied |

## Live demo on your machine

**Windows:** double-click `run_demo.bat`. **macOS/Linux:** `./run_demo.sh`.
The first run installs the dependencies into `venv` and takes a few minutes. The launcher starts the
mutual-TLS gateway on https://127.0.0.1:8443 and opens the dashboard at **http://localhost:8501**.

The **Live plant** page runs the gateway and the plant in real time. Use the buttons on the left
to launch a stolen-key false-data attack, a rogue device, a finger photo held up to the camera, or
a genuine hardware fault, and watch the gateway respond. **Scripted scenarios** runs the seven
end-to-end scenarios below.

## Quickstart

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m pytest tests -q                 # 36 tests, includes real mutual-TLS sockets
python -m sensetrust.scenarios            # the seven scenarios, PASS/FAIL
streamlit run dashboard/app.py            # live demo dashboard
python -m sensetrust.server --data data   # the gateway on https://127.0.0.1:8443 (mTLS)
python -m sensetrust.evaluate             # regenerate results/ (~10 min; --quick ~1.5 min)
```

Or run `docker compose up` for the gateway on :8443 and the dashboard on :8501.

## Layout

```
sensetrust/
  ca.py           plant CA: issue / verify / revoke X.509 (ECDSA P-256), TLS 1.3 contexts
  crypto.py       message signing, Ed25519 access tokens (sender-constrained), AES-256-GCM sealing
  gateway.py      policy enforcement point: identity -> integrity -> freshness -> behaviour -> policy
  policy.py       default-deny decisions for telemetry, commands (with biometric step-up), M2M
  trust.py        dynamic per-identity trust score, auto-quarantine
  replay.py       nonce / sequence / timestamp guard, token-bucket rate limiting
  anomaly.py      fault-vs-attack detector (analytical redundancy + IsolationForest)
  plant.py        water-treatment tank physics and level controller
  biometric.py    operator fingerprint + liveness, sealed templates, ISO/IEC 19794-4 records
  biometric_engine/   vendored unchanged from YellowSense's contactless fingerprint SDK
  server.py       HTTPS + mutual TLS front end
  site.py, simulation.py, scenarios.py, evaluate.py
dashboard/app.py  Streamlit demo
docs/architecture.md
application/      COMET application answers
```

## Status

**Technology readiness: proof of concept.** Everything above runs, and every number above is
reproducible from this repository. What it isn't yet:

- **Not field-tested.** The plant is simulated. Real deployment needs site historian data for
  calibration and an OPC UA / MQTT adapter.
- **Device keys live in files.** Production keys go in a TPM or secure element, with the CA root
  in an HSM.
- **Fingerprint accuracy on real phone captures isn't solved.** In the UIDAI SITAA PoC, a
  31-identity gallery measured an EER of about 43% with the production matcher (abhimanyu86/uidai,
  commit 3ba30f3). Closing that gap is a funded milestone.

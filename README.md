# SenseTrust — Zero-Trust security for industrial CPS/IoT

**YellowSense Technologies** · proof of concept for COMET 5G Springboard 6, Problem Statement 13
(Zero-Trust Security for CPS/IoT: device identity, authentication, secure access, encryption,
anomaly detection, secure APIs, machine-to-machine trust).

Industrial plants still trust whatever arrives on the plant network. SenseTrust checks every
reading, command and device-to-device message on its own merits, with three questions:

1. **Is this device who it says it is?** Mutual TLS 1.3 against a plant CA, with an ECDSA
   signature on every message. Devices generate their own keys and enrol with a one-time
   token; the CA never holds a device key. On private 5G, the device's SIM must match its
   certificate too.
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
| S8 | New device enrols; attacker reuses its token, asks for a higher role, uses an expired token; quarantined device tries to renew | Device identity lifecycle | CA never holds the key; every abuse refused; renewal rotates the key and retires the old certificate |
| S9 | Over MQTT (real Mosquitto broker): stolen LT-101 key posts as PT-101; rogue and certificate-less clients connect; LT-101 revoked | Secure APIs, encryption, M2M | broker refuses the publish (MQTT code 135) before the gateway; handshakes refused; revoked device's next message denied and reconnect refused |
| S10 | Private 5G: stolen SIM without the key; key on another SIM; command from a sensor's slice; closed maintenance slice | Device identity, secure access | all denied; a key seen on the wrong SIM is treated as stolen and revoked |
| S11 | Pilot-site shadow mode: SenseTrust may only read the PLC over OPC UA; the LT-101 transmitter behind the PLC is compromised; rogue and certificate-less clients connect; SenseTrust tries to write | Anomaly detection, secure access, encryption | attack flagged from physics in 3 s, incident ticket, nothing revoked; rogue and certificate-less clients refused; write refused |

S9 needs Mosquitto installed (it shows SKIP otherwise; see below). S11 needs `asyncua`
(in `requirements.txt`). S10 uses a sample subscriber
table (`config/5g_subscribers.json`); no live 5G core runs in this PoC.

## Live demo on your machine

**Windows:** double-click `run_demo.bat`. **macOS/Linux:** `./run_demo.sh`.
The first run installs the dependencies into `venv` and takes a few minutes. The launcher starts the
mutual-TLS gateway on https://127.0.0.1:8443 and opens the dashboard at **http://localhost:8501**.

The **Live plant** page runs the gateway and the plant in real time. Use the buttons on the left
to launch a stolen-key false-data attack, a rogue device, a finger photo held up to the camera, or
a genuine hardware fault, and watch the gateway respond. **Scripted scenarios** runs the ten
end-to-end scenarios above.

## Quickstart

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m pytest tests -q                 # 76 tests: real mTLS sockets, real MQTT broker, real OPC UA
python -m sensetrust.scenarios            # the eleven scenarios, PASS/FAIL
streamlit run dashboard/app.py            # live demo dashboard
python -m sensetrust.server --data data   # gateway https://127.0.0.1:8443 (mTLS), enrolment :8444
python -m sensetrust.evaluate             # regenerate results/ (~10 min; --quick ~1.5 min)
```

Or run `docker compose up` for the gateway (:8443, enrolment :8444) and the dashboard (:8501),
and `docker compose run --rm scenarios` for all eleven scenarios with Mosquitto included.

### MQTT (scenario S9)

The broker is Eclipse Mosquitto, configured by `sensetrust/mqtt.py`: TLS 1.3 only, client
certificate required, certificate CN used as the MQTT username, a topic ACL so each device can
publish only on `plant/telemetry/<its ID>`, and the CA's revocation list loaded (reloaded on
every revocation). Install it once:

- Ubuntu/Debian: `sudo apt install mosquitto`
- macOS: `brew install mosquitto`
- Windows: run the installer from https://mosquitto.org/download/ (default folder is fine).
  You do not need to start the Mosquitto service; the scenario starts its own broker.

SenseTrust looks for Mosquitto on the PATH and in `Program Files\mosquitto` (or `\mosquitto`)
on drives C, D and E. If it is somewhere else, set `MOSQUITTO` to its folder, e.g. in Git Bash:
`export MOSQUITTO="/d/Tools/mosquitto"`; in PowerShell: `$env:MOSQUITTO="D:\Tools\mosquitto"`.

Without Mosquitto, S9 and `tests/test_mqtt.py` are skipped and everything else runs.

### OPC UA shadow mode (scenario S11)

A pilot site will first let SenseTrust *read* its data and nothing else. `sensetrust/opcua.py`
does exactly that:

- `PlantOpcUaServer` stands in for the site's PLC or SCADA server (driven by the simulated
  plant). It offers only `Basic256Sha256` with `SignAndEncrypt`, so there is no unsecured
  endpoint. Its certificate comes from the plant CA. A client must present a plant-CA
  certificate that is not on the revocation list, and every value is read-only to clients.
- `OpcUaShadowMonitor` is SenseTrust's client. It checks that the server's certificate was
  issued by the plant CA to a PLC, reads all values once per second in one request, and passes
  them to `Gateway.shadow_tick`. That runs the same fault-vs-attack physics check, but only
  raises alerts and tickets: it never revokes, quarantines or writes anything.

OPC UA's security policy needs RSA keys, so OPC UA certificates are RSA-2048, signed by the same
plant CA (`ca.issue_opcua`). In shadow mode the PLC keeps acting on the bad reading (the tank in
S11 still overfills); preventing that is what enforcement mode (S2) adds once the site agrees.

### Device enrolment

A device creates its key, then redeems a one-time token with a certificate request:
`POST /v1/enrol {"token", "csr"}` on port 8444 (server-authenticated TLS; the device has no
certificate yet). Renewal is `POST /v1/renew {"csr"}` over mutual TLS with the current
certificate, and must use a new key. Certificates last 30 days. Tokens are single-use, expire
after 24 hours, store only a hash, and fix the device ID and role.

### Hardware-held keys (Linux)

`python tools/hsm_enrol_demo.py` (needs `sudo apt install softhsm2 opensc pkcs11-provider` and
`pip install python-pkcs11`) generates a device key inside a PKCS#11 token (SoftHSM, standing in
for a TPM or secure element), builds the CSR through the token, enrols, has the gateway accept a
reading signed inside the token, and shows the token refusing to reveal the key.

### Private 5G binding

`python -m sensetrust.server --5g-subscribers config/5g_subscribers.json` turns on the check
that a device's certificate, its SIM's fixed address and the slice it arrived on all agree with
the core's subscriber table. Commands are allowed only on the control slice, readings on the
telemetry slice, and the maintenance slice is closed by default.

## Layout

```
sensetrust/
  ca.py           plant CA: enrolment tokens, CSR issuance, renewal, revocation + CRL, TLS 1.3,
                  OPC UA application certificates
  devices.py      device side: generates its own key, enrols, renews, signs every message
  mqtt.py         Mosquitto broker config (mTLS, ACL, CRL), device client, gateway bridge
  opcua.py        OPC UA shadow mode: secured read-only PLC server (simulated) + SenseTrust monitor
  fiveg.py        private 5G binding: certificate + SIM address + slice must agree
  crypto.py       message signing, Ed25519 access tokens (sender-constrained), AES-256-GCM sealing
  gateway.py      policy enforcement point: identity -> integrity -> freshness -> behaviour -> policy
  policy.py       default-deny decisions for telemetry, commands (with biometric step-up), M2M
  trust.py        dynamic per-identity trust score, auto-quarantine
  replay.py       nonce / sequence / timestamp guard, token-bucket rate limiting
  anomaly.py      fault-vs-attack detector (analytical redundancy + IsolationForest)
  plant.py        water-treatment tank physics and level controller
  biometric.py    operator fingerprint + liveness, sealed templates, ISO/IEC 19794-4 records
  biometric_engine/   vendored unchanged from YellowSense's contactless fingerprint SDK
  server.py       HTTPS + mutual TLS front end; enrolment endpoint
  site.py, simulation.py, scenarios.py, evaluate.py
config/5g_subscribers.json   sample 5G core subscriber table
tools/hsm_enrol_demo.py      device key held in a PKCS#11 token
dashboard/app.py  Streamlit demo
docs/architecture.md
application/      COMET application answers
```

## Status

**Technology readiness: proof of concept.** Everything above runs, and every number above is
reproducible from this repository. What it isn't yet:

- **Not field-tested.** The plant is simulated, including the OPC UA server. The read-only
  OPC UA adapter and MQTT are built; a real deployment still needs site historian data for
  calibration and testing against the site's actual PLC or SCADA server.
- **Device keys are generated on the device but stored in files.** The CA holds none of them.
  `tools/hsm_enrol_demo.py` shows enrolment and message signing with a key that cannot leave a
  PKCS#11 token, but Python's TLS library cannot use such a key, so the TLS handshake in this
  PoC still uses a file key. Device firmware (mbedTLS, wolfSSL) does this natively; the CA root
  belongs in an HSM.
- **5G binding is tested against sample core data, not a live 5G core.** Running it end to end
  on a private 5G network is planned for the COMET testbed.
- **Fingerprint accuracy on real phone captures isn't solved.** In the UIDAI SITAA PoC, a
  31-identity gallery measured an EER of about 43% with the production matcher (abhimanyu86/uidai,
  commit 3ba30f3). Closing that gap is a funded milestone.

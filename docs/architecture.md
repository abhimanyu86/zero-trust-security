# SenseTrust architecture

## Problem

Industrial control systems were built on implicit trust. A reading from a transmitter
counts as the truth because it arrives on the plant network. A command from the HMI gets
executed because it came from the HMI. Once an attacker is inside, whether through a stolen
device key, a compromised laptop or a rogue device plugged into a switch, nothing questions
them. The anomaly tools that do exist mostly say *something is wrong*. They can't say whether
a technician or an incident responder should be sent.

## Principles applied

| Zero-trust principle | How SenseTrust applies it |
|---|---|
| Never trust the network location | Mutual TLS 1.3 on every connection. A client without a plant-CA certificate fails the handshake. |
| Strong identity for every subject | Every sensor, actuator, console and the gateway itself holds an ECDSA P-256 X.509 certificate. Human operators use contactless fingerprint plus liveness. |
| Verify every request explicitly | Signature, freshness (timestamp, nonce, sequence), rate, trust score and policy are checked on each request. Nothing is cached as "already authenticated". |
| Least privilege | Roles (sensor, actuator, console) and operator scopes (actuate, override, admin). Tokens are short-lived and bound to one console's certificate. |
| Assume breach | Even a *correctly keyed* device is checked against plant physics. A device caught lying is quarantined and its certificate revoked in the same second. |
| Continuous verification | Critical commands need a fingerprint check less than 5 minutes old, or less than 30 seconds while the plant is under attack. |

## Components

```
                       ┌───────────────────────── Plant CA (ca.py) ─────────────────────────┐
                       │  issue / verify / revoke X.509 (ECDSA P-256), revocation on every  │
                       │  request                                                           │
                       └────────────────────────────────────────────────────────────────────┘
  Sensors                                    Gateway (gateway.py)                        Operators
  LT-101 PT-101 FT-101 ──mTLS 1.3──►  1 identity    certificate + role                ◄──mTLS── console-01/02
  signed telemetry                    2 integrity   ECDSA signature on payload            fingerprint + liveness
  (devices.py)                        3 freshness   ts / nonce / seq (replay.py)          (biometric.py, reused
                                      4 behaviour   rate limit, trust score (trust.py)     from the UIDAI SDK)
  P-101 ◄── M2M level feed ──LT-101   5 policy      allow / deny / step-up (policy.py)    ──► short-lived token
     asks gateway: trust this peer?   6 evidence    denials -> trust + detector            bound to console cert
                                      ─────────────────────────────────────────────
                                      7 physics     fault vs attack (anomaly.py)
                                      8 response    attack  -> quarantine + revoke
                                                    fault   -> ticket, out of control loop
                                                    ambiguous -> ticket + reduced trust
                                      Sealed storage: AES-256-GCM (templates, telemetry)
```

## Telling a fault from an attack

The three instruments are physically linked. Level and pressure must agree through
hydrostatics. Level must change the way pump inflow minus metered outflow says it should.
Each sensor is predicted from the others, and its residual is normalised by its own noise.
Thresholds come from normal operation only.

When a residual persists:

1. **Isolate:** the sensor with the largest normalised residual is the suspect.
2. **Classify** using the suspect's own signal:
   - Missing samples, out-of-range values, a frozen value, or a noise burst look like failing hardware → **fault**.
   - A bad signature, replay or rate abuse on the same device's channel → **attack**.
   - A healthy-looking signal (normal noise, in range) that contradicts physics, either through a sudden step or through fast divergence → **attack**.
   - Slow, smooth divergence → **ambiguous**. Calibration drift and a patient stealth ramp can't be separated from process data alone, so the system says so. It raises an inspection ticket and reduces trust, but doesn't auto-revoke.
3. An IsolationForest trained on normal residuals is a model-free backstop.

A **fault** keeps the device's identity but removes its value from control loops: the pump
controller falls back to the gateway's physics-consistent level. An **attack** triggers
quarantine and certificate revocation. The device's next message fails at the identity
check.

## What is PoC and what is production-grade

| Area | PoC state | Path to production |
|---|---|---|
| PKI | Single-tier CA; the revocation list is a JSON file checked on every request | Two-tier CA with an HSM-held root; OCSP stapling; hardware-backed keys (TPM / secure element) |
| Transport | Python HTTPS + mTLS | Same pattern on MQTT-over-TLS and OPC UA; mbedTLS/wolfSSL on devices |
| Detector | 3-instrument simulated plant | Plant-specific models built from P&IDs and historian data; per-site calibration |
| Biometrics | UIDAI SDK matcher + FFT replay detector on synthetic data | Real-capture accuracy work (EER), on-device pipeline, calibrated liveness |
| Policy | Python rules | Policy-as-code (e.g. OPA/Rego) with signed policy bundles |
| 5G | Not used | Network-slice-aware policy and SIM/eSIM-anchored device identity |

"""
Hardware-held device key, end to end (Linux; uses SoftHSM as a stand-in for a TPM or
secure element, through the same PKCS#11 interface real chips expose).

    sudo apt install softhsm2 opensc pkcs11-provider
    pip install python-pkcs11
    python tools/hsm_enrol_demo.py

What it shows:
  1. The device key is generated INSIDE the token, marked sensitive and never extractable.
  2. OpenSSL builds the CSR by asking the token to sign; the key never leaves it.
  3. SenseTrust enrols the device with a one-time token, as for any other device.
  4. A reading signed inside the token is accepted by the gateway.
  5. Trying to read the private key out of the token fails.

Limit, stated plainly: Python's TLS library cannot use a key it cannot read, so in this
PoC the TLS handshake still uses a file key. Device firmware (mbedTLS, wolfSSL) does TLS
with secure-element keys natively; that integration is roadmap work.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODULE_CANDIDATES = ["/usr/lib/softhsm/libsofthsm2.so",
                     "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                     "/usr/local/lib/softhsm/libsofthsm2.so"]
PROVIDER_CANDIDATES = ["/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
                       "/usr/lib/aarch64-linux-gnu/ossl-modules/pkcs11.so"]
PIN, DEVICE = "1111", "LT-102"


def run(cmd, env, check=True):
    p = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if check and p.returncode != 0:
        sys.exit("command failed: %s\n%s%s" % (" ".join(cmd), p.stdout, p.stderr))
    return p


def step(n, text):
    print("\n[%d] %s" % (n, text))


def main():
    module = next((m for m in MODULE_CANDIDATES if os.path.exists(m)), None)
    provider = next((p for p in PROVIDER_CANDIDATES if os.path.exists(p)), None)
    missing = [n for n, ok in (("softhsm2", module), ("pkcs11-provider", provider),
                               ("pkcs11-tool (opensc)", shutil.which("pkcs11-tool")))
               if not ok]
    if missing:
        sys.exit("missing: %s  (sudo apt install softhsm2 opensc pkcs11-provider)" % ", ".join(missing))

    import pkcs11
    from pkcs11 import KeyType, ObjectClass, Mechanism
    from pkcs11.util.ec import encode_ecdsa_signature

    from sensetrust.crypto import b64e, canonical, new_nonce
    from sensetrust.gateway import Gateway

    work = tempfile.mkdtemp(prefix="hsm-demo-")
    os.makedirs(os.path.join(work, "tokens"))
    env = dict(os.environ)
    env["SOFTHSM2_CONF"] = os.path.join(work, "softhsm2.conf")
    with open(env["SOFTHSM2_CONF"], "w") as f:
        f.write("directories.tokendir = %s/tokens\nobjectstore.backend = file\n" % work)
    env["OPENSSL_CONF"] = os.path.join(work, "openssl.cnf")
    with open(env["OPENSSL_CONF"], "w") as f:
        f.write("openssl_conf = init\n[init]\nproviders = prov\n[prov]\ndefault = dflt\npkcs11 = p11\n"
                "[dflt]\nactivate = 1\n[p11]\nmodule = %s\npkcs11-module-path = %s\n"
                "pkcs11-module-token-pin = %s\nactivate = 1\n" % (provider, module, PIN))
    os.environ.update(SOFTHSM2_CONF=env["SOFTHSM2_CONF"])

    step(1, "Generate %s's key INSIDE the token (sensitive, never extractable)" % DEVICE)
    run(["softhsm2-util", "--init-token", "--free", "--label", "device", "--so-pin", "5678",
         "--pin", PIN], env)
    run(["pkcs11-tool", "--module", module, "--token-label", "device", "--login", "--pin", PIN,
         "--keypairgen", "--key-type", "EC:prime256v1", "--label", DEVICE, "--id", "01",
         "--usage-sign", "--sensitive"], env)
    listing = run(["pkcs11-tool", "--module", module, "--token-label", "device", "--login",
                   "--pin", PIN, "--list-objects", "--type", "privkey"], env).stdout
    print("    " + next(l.strip() for l in listing.splitlines() if "Access" in l))

    step(2, "Build the certificate request; the token does the signing")
    csr_path = os.path.join(work, DEVICE + ".csr")
    uri = "pkcs11:token=device;object=%s;type=private" % DEVICE
    run(["openssl", "req", "-new", "-key", uri, "-subj", "/CN=" + DEVICE, "-out", csr_path], env)
    print("    CSR written: %s" % csr_path)

    step(3, "Enrol with a one-time token, exactly like any other SenseTrust device")
    gw = Gateway(os.path.join(work, "gateway"))
    token = gw.ca.create_enrolment_token(DEVICE, "sensor")
    cert = gw.ca.enrol(token, open(csr_path, "rb").read())
    print("    issued: %s, valid until %s" % (cert.subject.rfc4514_string(),
                                              cert.not_valid_after_utc.date()))
    print("    CA holds a key for %s: %s" % (DEVICE, os.path.exists(gw.ca.paths(DEVICE)[0])))

    step(4, "Sign a reading inside the token and send it to the gateway")
    lib = pkcs11.lib(module)
    tok = lib.get_token(token_label="device")
    with tok.open(user_pin=PIN) as session:
        priv = session.get_key(ObjectClass.PRIVATE_KEY, KeyType.EC, label=DEVICE)
        body = {"device_id": DEVICE, "nonce": new_nonce(), "ts": time.time(), "seq": 1, "value": 1.42}
        # Hash on the host, sign the digest in the token (CKM_ECDSA); same result as
        # ECDSA-SHA256, which not every token implements as one mechanism.
        import hashlib
        raw = priv.sign(hashlib.sha256(canonical(body)).digest(), mechanism=Mechanism.ECDSA)
        envelope = {"body": body, "sig": b64e(encode_ecdsa_signature(raw))}
    decision = gw.telemetry(cert, envelope)
    print("    gateway decision: %s (%s)" % (decision["effect"], "; ".join(decision["reasons"])))

    step(5, "Try to read the private key out of the token")
    with tok.open(user_pin=PIN) as session:
        priv = session.get_key(ObjectClass.PRIVATE_KEY, KeyType.EC, label=DEVICE)
        try:
            priv[pkcs11.Attribute.VALUE]
            print("    UNEXPECTED: key material was readable")
            ok = False
        except pkcs11.exceptions.PKCS11Error as e:
            print("    refused by the token: %s" % type(e).__name__)
            ok = True
    gw.close()
    print("\nRESULT: %s" % ("PASS" if ok and decision["effect"] == "allow" else "FAIL"))
    sys.exit(0 if ok and decision["effect"] == "allow" else 1)


if __name__ == "__main__":
    main()

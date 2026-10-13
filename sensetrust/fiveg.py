"""
5G binding: a device must prove who it is twice, independently.

  - Its certificate, checked in the TLS handshake and on every message (the rest of
    SenseTrust).
  - Its SIM. A private 5G core authenticates every SIM itself (5G-AKA) and, configured
    this way, gives each SIM a fixed IP address from the pool of one slice. With local
    breakout (the user-plane function on the plant LAN, no NAT), that address is the
    source address the gateway sees.

The gateway checks that certificate, source address and slice all agree with the
device's enrolment record. An attacker then needs both the SIM and the key of the same
device. Slices separate traffic by purpose: commands only on the control slice,
readings on the telemetry slice, vendor access on a maintenance slice that is closed
unless an administrator opens it.

Input is the subscriber table provisioned in the 5G core (for Open5GS: subscriber
records with a static UE IP, plus the per-DNN address pools in smf.yaml), loaded from
JSON. In this PoC that table is sample data; checking against a live core is roadmap
work on the COMET 5G testbed.

Identities that are not 5G subscribers (wired consoles, wired PLC adapters) are not
affected, but nobody may use a 5G address without being the subscriber it belongs to.
"""

import ipaddress
import json

# Which kind of traffic each slice may carry.
SLICE_ALLOWS = {
    "control": {"command", "m2m"},
    "telemetry": {"telemetry", "m2m"},
    "maintenance": {"telemetry", "command", "m2m"},
}


class FiveGBinding:

    def __init__(self, slices, subscribers):
        """
        slices:      {"telemetry": {"pool": "10.46.0.0/24", "sst": 1, "sd": "000002"}, ...}
        subscribers: [{"identity": "LT-101", "supi": "imsi-...", "ip": "10.46.0.11",
                       "slice": "telemetry"}, ...]
        """
        self.slices = {name: {**spec, "net": ipaddress.ip_network(spec["pool"])}
                       for name, spec in slices.items()}
        self.by_identity = {s["identity"]: s for s in subscribers}
        self.by_ip = {s["ip"]: s for s in subscribers}
        self.maintenance_open = False
        for s in subscribers:
            net = self.slices[s["slice"]]["net"]
            if ipaddress.ip_address(s["ip"]) not in net:
                raise ValueError("%s: %s is outside the %s pool" % (s["identity"], s["ip"], s["slice"]))

    @classmethod
    def load(cls, path):
        with open(path) as f:
            data = json.load(f)
        return cls(data["slices"], data["subscribers"])

    def slice_of(self, ip):
        addr = ipaddress.ip_address(ip)
        for name, spec in self.slices.items():
            if addr in spec["net"]:
                return name
        return None

    def check(self, identity, kind, source_ip):
        """Returns (ok, reason). kind: 'telemetry' | 'command' | 'm2m'."""
        if source_ip is None:
            return True, "no source address (transport-internal call)"
        slice_name = self.slice_of(source_ip)
        sub = self.by_identity.get(identity)
        if slice_name is None:
            if sub is not None:
                return False, ("%s is a 5G subscriber but this came from %s, outside every slice"
                               % (identity, source_ip))
            return True, "not a 5G path"
        owner = self.by_ip.get(source_ip)
        if owner is None:
            return False, "%s on the %s slice belongs to no enrolled SIM" % (source_ip, slice_name)
        if owner["identity"] != identity:
            return False, ("certificate is %s but %s is the SIM address of %s"
                           % (identity, source_ip, owner["identity"]))
        if slice_name == "maintenance" and not self.maintenance_open:
            return False, "maintenance slice is closed"
        if kind not in SLICE_ALLOWS[slice_name]:
            return False, "%s traffic is not allowed on the %s slice" % (kind, slice_name)
        return True, "SIM %s, %s slice" % (owner["supi"], slice_name)

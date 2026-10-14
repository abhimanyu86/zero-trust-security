"""
Operator authentication: contactless fingerprint + presentation-attack detection.

This is YellowSense's contactless fingerprint SDK (UIDAI SITAA work) used as the human
factor of zero trust: before an operator can issue a critical command to the plant, the
gateway checks the finger, not just a password or a badge.

The engine modules in `biometric_engine/` are vendored unchanged from the SDK
(abhimanyu86/uidai, backend/): the minutiae matcher, the FFT screen-replay detector and
the ISO/IEC 19794-4 Finger Image Record encoder. In the full SDK the minutiae come from
the phone camera pipeline (YOLO -> liveness CNN -> U2-Net -> MinutiaeNet); here they are
supplied by the caller, so this module runs with no model weights.

Templates are sealed with AES-256-GCM before they are written anywhere, with the operator
ID bound in as associated data: a stolen template file is useless, and one operator's
sealed template cannot be swapped in for another's.
"""

import base64
import json
import os
import sys
from dataclasses import dataclass, field

import cv2

_ENGINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "biometric_engine")
if _ENGINE not in sys.path:
    sys.path.insert(0, _ENGINE)

from fir import decode_fir, encode_fir  # noqa: E402
from matching import match_templates  # noqa: E402
from spoof_detection import detect_screen_replay  # noqa: E402

# Of the SDK's registered matchers, RANSAC rigid alignment separated genuine from
# impostor best on the harsh synthetic recaptures (30% minutiae dropped, 20% spurious,
# rotated) — see results/metrics.json. Real-capture accuracy is a separate, open item.
MATCH_ALGORITHM = "ransac_alignment"
MATCH_THRESHOLD = 0.30


@dataclass
class BiometricResult:
    ok: bool
    operator_id: str
    score: float = 0.0
    live: bool = False
    reasons: list = field(default_factory=list)
    spoof: dict = field(default_factory=dict)


class OperatorRegistry:

    def __init__(self, store, path):
        self.store = store
        self.path = path
        self._records = {}
        if os.path.exists(path):
            with open(path) as f:
                self._records = json.load(f)

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._records, f)
        os.replace(tmp, self.path)

    def enroll(self, operator_id, role, minutiae, image_bgr, scopes):
        gray = cv2.cvtColor(image_bgr, cv2.COLOR_BGR2GRAY) if image_bgr.ndim == 3 else image_bgr
        fir = encode_fir(gray, finger_position=2)      # right index finger
        record = {"role": role, "scopes": sorted(scopes), "minutiae": minutiae,
                  "fir_19794_4": base64.b64encode(fir).decode()}
        self._records[operator_id] = self.store.seal("operator:" + operator_id, record)
        self._save()
        return len(fir)

    def exists(self, operator_id):
        return operator_id in self._records

    def profile(self, operator_id):
        rec = self.store.open(self._records[operator_id], "operator:" + operator_id)
        return {"role": rec["role"], "scopes": rec["scopes"]}

    def enrolled_fir(self, operator_id):
        """Decode the stored ISO/IEC 19794-4 record (demonstrates conformance by round trip)."""
        rec = self.store.open(self._records[operator_id], "operator:" + operator_id)
        return decode_fir(base64.b64decode(rec["fir_19794_4"]))

    def verify(self, operator_id, minutiae, image_bgr):
        if operator_id not in self._records:
            return BiometricResult(False, operator_id, reasons=["unknown operator"])
        rec = self.store.open(self._records[operator_id], "operator:" + operator_id)
        spoof = detect_screen_replay(image_bgr)
        live = not spoof["is_screen"]
        score = match_templates(rec["minutiae"], minutiae, algorithm=MATCH_ALGORITHM)
        reasons = []
        if not live:
            reasons.append("presentation attack: screen/print recapture detected")
        if score < MATCH_THRESHOLD:
            reasons.append("fingerprint does not match (score %.2f < %.2f)" % (score, MATCH_THRESHOLD))
        return BiometricResult(not reasons, operator_id, round(float(score), 3), live, reasons,
                               {k: spoof[k] for k in ("peak_count", "chroma_diff", "score", "note")})

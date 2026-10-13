"""
The gateway on the network: HTTPS with mutual TLS 1.3.

A client that cannot present a certificate issued by the plant CA never gets past the TLS
handshake — its request is not parsed, logged or rate-limited, because it never exists as
a request. The certificate the handshake verified is then handed to the Gateway, which
re-checks it (revocation takes effect immediately, even on an open connection) and
applies policy.

    python -m sensetrust.server --data data --port 8443

Endpoints (JSON over POST):
    /v1/telemetry          signed envelope                        (sensors)
    /v1/m2m/authorize      {"msg_type", "envelope", "peer_cert"}  (devices asking about a peer)
    /v1/operator/login     {"operator_id", "minutiae", "image_png_b64"}   (consoles)
    /v1/command            {"token", "envelope"}                  (consoles)
    /v1/state              GET, current trust / quarantine / events

Enrolment runs on a second port (default 8444), because a new device has no certificate
yet. That listener authenticates the server only; the device proves itself with a
one-time token and a CSR signed by its own key (the EST pattern, RFC 7030):
    /v1/enrol              {"token", "csr"}  -> {"cert"}             (no client cert needed)
    /v1/renew              {"csr"}           -> {"cert"}             (current client cert required)
"""

import argparse
import base64
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import cv2
import numpy as np
from cryptography.hazmat.primitives import serialization

from .ca import EnrolmentError
from .gateway import Gateway

MAX_BODY = 1 << 20


def make_handler(gw):

    class Handler(BaseHTTPRequestHandler):
        server_version = "SenseTrust/0.1"

        def log_message(self, fmt, *args):
            pass

        def _peer_cert(self):
            return self.connection.getpeercert(binary_form=True)

        def _send(self, code, obj):
            data = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/state":
                ok, reason, _, role = gw.ca.verify(self._peer_cert())
                if not ok or role != "console":
                    return self._send(403, {"error": "state is visible to operator consoles only"})
                return self._send(200, gw.state())
            self._send(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                req = json.loads(self.rfile.read(length))
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            cert = self._peer_cert()
            if self.path == "/v1/telemetry":
                d = gw.telemetry(cert, req)
            elif self.path == "/v1/m2m/authorize":
                d = gw.authorize_m2m(req.get("peer_cert"), req.get("envelope", {}), req.get("msg_type"))
            elif self.path == "/v1/operator/login":
                img = cv2.imdecode(np.frombuffer(base64.b64decode(req["image_png_b64"]), np.uint8),
                                   cv2.IMREAD_COLOR)
                d = gw.operator_login(cert, req["operator_id"], req["minutiae"], img)
            elif self.path == "/v1/command":
                d = gw.command(cert, req.get("token", ""), req.get("envelope", {}))
            else:
                return self._send(404, {"error": "not found"})
            allowed = d.get("effect") == "allow" or d.get("ok") is True
            self._send(200 if allowed else 403, d)

    return Handler


def serve(gw, host="127.0.0.1", port=8443, identity="gateway"):
    httpd = ThreadingHTTPServer((host, port), make_handler(gw))
    httpd.socket = gw.ca.server_context(identity).wrap_socket(httpd.socket, server_side=True)
    return httpd


def make_enrolment_handler(gw):

    class Handler(BaseHTTPRequestHandler):
        server_version = "SenseTrust-EST/0.1"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length > 64 * 1024:
                return self._send(413, {"error": "body too large"})
            try:
                req = json.loads(self.rfile.read(length))
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            try:
                if self.path == "/v1/enrol":
                    cert = gw.ca.enrol(req.get("token", ""), req.get("csr", ""))
                    who = cert.subject.rfc4514_string()
                    gw._event("enrolled", "info", who, "device enrolled with its own key")
                elif self.path == "/v1/renew":
                    peer = self.connection.getpeercert(binary_form=True)
                    if peer is None:
                        raise EnrolmentError("renewal refused: no client certificate")
                    cert = gw.ca.renew(peer, req.get("csr", ""))
                    gw._event("renewed", "info", cert.subject.rfc4514_string(),
                              "certificate renewed with a new key")
                else:
                    return self._send(404, {"error": "not found"})
            except EnrolmentError as e:
                gw._event("enrolment_denied", "warning", "unknown", str(e))
                return self._send(403, {"error": str(e)})
            self._send(200, {"cert": cert.public_bytes(serialization.Encoding.PEM).decode()})

    return Handler


def serve_enrolment(gw, host="127.0.0.1", port=8444, identity="gateway"):
    """Server-authenticated TLS 1.3; a client certificate is optional (only /v1/renew needs it)."""
    key_path, crt_path = gw.ca.paths(identity)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(crt_path, key_path)
    ctx.load_verify_locations(gw.ca.ca_cert_path)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    httpd = ThreadingHTTPServer((host, port), make_enrolment_handler(gw))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def post(ctx, host, port, path, obj):
    """Minimal mTLS client used by the device simulator and tests."""
    import http.client
    conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    try:
        body = json.dumps(obj, default=str)
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        return r.status, json.loads(r.read())
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--enrol-port", type=int, default=8444)
    a = ap.parse_args()
    gw = Gateway(a.data)
    if not os.path.exists(gw.ca.paths("gateway")[1]):
        gw.ca.issue("gateway", "gateway", hostnames=("localhost", "127.0.0.1", a.host))
    httpd = serve(gw, a.host, a.port)
    est = serve_enrolment(gw, a.host, a.enrol_port)
    import threading
    threading.Thread(target=est.serve_forever, daemon=True).start()
    print("SenseTrust gateway on https://%s:%d (mutual TLS 1.3, CA %s)" % (a.host, a.port, gw.ca.ca_cert_path))
    print("Device enrolment on https://%s:%d (one-time token + CSR)" % (a.host, a.enrol_port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()


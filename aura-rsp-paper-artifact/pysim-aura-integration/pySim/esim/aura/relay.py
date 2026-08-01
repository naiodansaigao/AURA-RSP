"""Shared Privacy Relay used by the integrated AURA-RSP mode."""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import ssl

import requests

from .codec import b64e, canonical, load_json


ROOT = Path(__file__).resolve().parents[3]
MAX_BODY = 1_000_000


class RelayState:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.config = load_json(root / "config" / "aura.json")
        self.runtime = root / "runtime" / "aura"
        self.key = (self.runtime / "pr-shared-key.bin").read_bytes()
        self.http = requests.Session()
        self.http.trust_env = False
        self.http.verify = str(
            root
            / "smdpp-data"
            / "generated"
            / "CertificateIssuer"
            / "CERT_CI_ECDSA_NIST.pem"
        )
        backend_host = requests.utils.urlparse(
            self.config["backend_url"]
        ).hostname
        original_getaddrinfo = socket.getaddrinfo

        def local_test_resolver(host, port, *args, **kwargs):
            # Keep the certificate/SNI hostname while resolving the local
            # research SM-DP+ without changing the user's /etc/hosts.
            if host == backend_host:
                host = "127.0.0.1"
            return original_getaddrinfo(host, port, *args, **kwargs)

        socket.getaddrinfo = local_test_resolver

    def forward(self, path: str, body: bytes) -> requests.Response:
        nonce = secrets.token_hex(16)
        authenticated = {
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "nonce": nonce,
            "PRaddr": self.config["praddr"],
        }
        tag = b64e(
            hmac.new(self.key, canonical(authenticated), hashlib.sha256).digest()
        )
        return self.http.post(
            self.config["backend_url"] + path,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Admin-Protocol": "aura/rsp/v14",
                "X-AURA-PRADDR": self.config["praddr"],
                "X-AURA-PR-NONCE": nonce,
                "X-AURA-PR-AUTH": tag,
            },
            timeout=30,
        )


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "AURA-Integrated-PR/1"

    @property
    def state(self) -> RelayState:
        return self.server.state

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_error(404)
            return
        body = canonical({"status": "ok", "role": "privacy-relay"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            json.loads(body)
            response = self.state.forward(self.path, body)
            self.send_response(response.status_code)
            if response.content:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
        except Exception as exc:
            body = canonical(
                {"error": "RELAY_EXCEPTION", "detail": type(exc).__name__}
            )
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    state = RelayState()
    port = args.port or int(state.config["relay_port"])
    server = ThreadingHTTPServer((args.host, port), RelayHandler)
    server.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pki = state.runtime / "pki"
    context.load_cert_chain(
        pki / "relay-server.pem", pki / "relay-server-key.pem"
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"AURA_INTEGRATED_PR_READY https://{args.host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

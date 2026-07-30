from __future__ import annotations

import argparse
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from .codec import canonical, load_json


ROOT = Path(__file__).resolve().parents[2]
MAX_BODY = 1_000_000


class RelayState:
    def __init__(self, root: Path):
        self.root = root
        self.config = load_json(root / "config" / "aura.json")
        self.runtime = root / "runtime"
        self.log_path = root / "logs" / "aura-relay.jsonl"
        self.http = requests.Session()
        self.http.trust_env = False

    def forward(self, path: str, body: bytes) -> tuple[int, bytes, float]:
        started = time.perf_counter()
        pki = self.runtime / "pki"
        response = self.http.post(
            self.config["backend_url"] + path,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-AURA-PRADDR": self.config["praddr"],
            },
            timeout=120,
            verify=str(pki / "ca.pem"),
            cert=(
                str(pki / "relay-client.pem"),
                str(pki / "relay-client-key.pem"),
            ),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        record = {
            "ts": time.time(),
            "event": "forward",
            "path": path,
            "status": response.status_code,
            "request_bytes": len(body),
            "response_bytes": len(response.content),
            "relay_ms": round(elapsed_ms, 3),
        }
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return response.status_code, response.content, elapsed_ms


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "AURA-Privacy-Relay/0.1"

    @property
    def state(self) -> RelayState:
        return self.server.state

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/health":
            data = canonical({"status": "ok", "role": "privacy-relay"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            status, response_body, relay_ms = self.state.forward(self.path, body)
            self.send_response(status)
            if response_body:
                self.send_header("Content-Type", "application/json")
            self.send_header("X-AURA-Relay-Ms", f"{relay_ms:.3f}")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            if response_body:
                self.wfile.write(response_body)
        except Exception as exc:
            data = canonical(
                {"error": "RELAY_EXCEPTION", "detail": f"{type(exc).__name__}: {exc}"}
            )
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    state = RelayState(ROOT)
    port = args.port or int(state.config["relay_port"])
    server = ThreadingHTTPServer((args.host, port), RelayHandler)
    server.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pki = state.runtime / "pki"
    context.load_cert_chain(
        pki / "relay-server.pem", pki / "relay-server-key.pem"
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"AURA_RELAY_READY https://{args.host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

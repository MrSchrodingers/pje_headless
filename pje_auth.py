# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import json
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict
from urllib.parse import parse_qs, unquote_plus, urlparse

import requests
from asn1crypto import core, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from requests.adapters import HTTPAdapter

# ------------------------ Config ------------------------
PJE_VERSION = "2.5.16"
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 10
SUCCESS_CODES = {200, 201, 202, 204, 302, 304}

log = logging.getLogger("pjeoffice")
if not log.handlers:
    logging.basicConfig(
      level=logging.INFO, 
      format="%(asctime)s %(levelname)s %(name)s: %(message)s"
      )

# ------------------------ GIFs 1×1 e 2×1 ----------------
GIF_OK = base64.b64decode("R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw==")
GIF_ERR = base64.b64decode("R0lGODlhAgABAPAAAP///wAAACH5BAAAAAAALAAAAAACAAEAAAICRAEAOw==")

# ------------------------ ASN.1 helper -------------------
class PkiPath(core.SequenceOf):
    _child_spec = x509.Certificate

# ------------------------ Server ------------------------
class DualStackServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

# ------------------------ PasswordSafe ------------------
class PasswordSafe:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._passwords: Dict[str, bytes] = {}
    def get(self, serial_hex: str) -> bytes | None:
        with self._lock:
            return self._passwords.get(serial_hex)
    def remember(self, serial_hex: str, password: bytes) -> None:
        with self._lock:
            self._passwords[serial_hex] = password

# ------------------------ PKCS12Token -------------------
class PKCS12Token:
    def __init__(self, path: str, password: str, safe: PasswordSafe | None = None) -> None:
        self.path = Path(path)
        self._password = password.encode("utf-8")
        self.safe = safe or PasswordSafe()
        self._key = None
        self._cert = None
        self._extra = None
        self._lock = threading.RLock()

    def login(self) -> None:
        with self._lock:
            if self._key is not None:
                return
            data = self.path.read_bytes()
            key, cert, extra = load_key_and_certificates(data, self._password)
            if key is None or cert is None:
                raise RuntimeError("certificate does not contain a private key")
            serial_hex = format(cert.serial_number, "x")
            self.safe.remember(serial_hex, self._password)
            self._key, self._cert, self._extra = key, cert, extra or []

    def _digest_for(self, algorithm: str):
        alg = (algorithm or "").upper()
        if "SHA256" in alg:
            return hashes.SHA256()
        if "SHA1" in alg or "SHA-1" in alg:
            return hashes.SHA1()
        if "MD5" in alg or "MD5WITHRSA" in alg:
            return hashes.MD5()
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    def sign(self, phrase: str, algorithm: str) -> str:
        if self._key is None:
            raise RuntimeError("token not logged in")
        signature = self._key.sign(
          phrase.encode("utf-8"), 
          padding.PKCS1v15(), 
          self._digest_for(algorithm)
          )
        return base64.b64encode(signature).decode("ascii")

    def certificate_chain_pkipath64(self) -> str:
        if self._cert is None:
            raise RuntimeError("token not logged in")
        chain = [self._cert, *(self._extra or [])]  # alvo -> âncora
        certs = [x509.Certificate.load(c.public_bytes(Encoding.DER)) for c in chain]
        der = PkiPath(certs).dump()  # << fix: define child_spec via subclass
        return base64.b64encode(der).decode("ascii")

# ------------------------ Authenticator -----------------
class Authenticator:
    def __init__(self, token: PKCS12Token) -> None:
        self.token = token
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def process(self, payload: Dict[str, Any]) -> None:
        task = json.loads(payload["tarefa"])
        mensagem: str = task["mensagem"]
        enviar_para: str = task["enviarPara"]
        uuid: str = task["token"]
        servidor: str = payload["servidor"]
        target = servidor + enviar_para

        self.token.login()
        assinatura_b64 = self.token.sign(mensagem, task.get("algoritmoAssinatura", "MD5withRSA"))
        cert_chain_b64 = self.token.certificate_chain_pkipath64()

        body = {
            "uuid": uuid,
            "mensagem": mensagem,
            "assinatura": assinatura_b64,
            "certChain": cert_chain_b64,
        }

        headers = {
            "versao": payload.get("versao", PJE_VERSION),
            "Accept": "application/json",
            "User-Agent": f"PJeOffice/{PJE_VERSION}",
            "Accept-Encoding": "gzip,deflate",
        }
        sessao = payload.get("sessao")
        if sessao:
            headers["Cookie"] = sessao

        resp = self.session.post(
            target,
            json=body,
            headers=headers,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=False,
        )

        if resp.status_code in SUCCESS_CODES:
            log.info("remote_post OK code=%s target=%s", resp.status_code, target)
            return

        snippet = (resp.text or "")[:400].replace("\n", " ")
        log.error("remote_post FAIL code=%s target=%s resp=%s", resp.status_code, target, snippet)
        resp.raise_for_status()

# ------------------------ HTTP Handler ------------------
class PJeRequestHandler(BaseHTTPRequestHandler):
    authenticator: Authenticator | None = None

    def _cors(self) -> None:
        origin = self.headers.get("Origin", "*")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Vary", "Origin")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        req_headers = self.headers.get("Access-Control-Request-Headers", "")
        if req_headers:
            self.send_header("Access-Control-Allow-Headers", req_headers)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/pjeOffice/":
            self._write_gif(GIF_OK)
            return
        if parsed.path != "/pjeOffice/requisicao/":
            self.send_response(404)
            self._cors()
            self.end_headers()
            return

        params = parse_qs(parsed.query)
        r_values = params.get("r")
        if not r_values:
            self._write_gif(GIF_ERR)
            return

        try:
            payload = json.loads(unquote_plus(r_values[0]))
            assert self.authenticator is not None, "Authenticator not configured"
            self.authenticator.process(payload)
            self._write_gif(GIF_OK)
        except Exception as e:
            log.exception("execucao EXC: %s", e)
            self._write_gif(GIF_ERR)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length))
            assert self.authenticator is not None, "Authenticator not configured"
            self.authenticator.process(data)
            self._write_gif(GIF_OK)
        except Exception as e:
            log.exception("execucao POST EXC: %s", e)
            self._write_gif(GIF_ERR)

    def _write_gif(self, blob: bytes) -> None:
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(blob)
        except BrokenPipeError:
            pass

    def log_message(self, fmt: str, *args: Any) -> None:
        return

# ------------------------ Bootstrap ---------------------
def run_server(cert_path: str, password: str, port: int) -> None:
    token = PKCS12Token(cert_path, password)
    authenticator = Authenticator(token)
    PJeRequestHandler.authenticator = authenticator
    server = DualStackServer(("::", port), PJeRequestHandler)
    host, prt = server.server_address[:2]
    log.info("PJeOffice headless pronto em http://localhost:%s (bind %s)", prt, host)
    try:
        server.serve_forever()
    finally:
        server.server_close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Headless PJe authenticator (fiel ao Java)")
    parser.add_argument("--certificate", "-c", required=True, help="Caminho do PKCS#12 (A1)")
    parser.add_argument("--password", "-p", required=True, help="Senha do certificado")
    parser.add_argument("--port", "-P", type=int, default=8800, help="Porta local (default: 8800)")
    args = parser.parse_args()
    run_server(args.certificate, args.password, args.port)

#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


def rr(name, rrtype, value, ttl=300):
    return {"name": name, "type": rrtype, "ttl": ttl, "value": value}


class Handler(BaseHTTPRequestHandler):
    server_version = "anyns-fixtures/0"

    def log_message(self, fmt, *args):
        return

    def _json(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"ok": True})
            return
        if self.path == "/resolve/domains/alice.crypto":
            self.handle_unstoppable()
            return
        if self.path == "/resolve/domains/missing.crypto":
            self._json(404, {"message": "domain not found"})
            return
        if self.path == "/v1/names/alice.btc/zonefile":
            self.handle_stacks_bns()
            return
        if self.path == "/v1/names/missing.btc/zonefile":
            self._json(404, {"message": "name not found"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/hns/resolve":
            self.handle_hns()
            return
        if self.path == "/namecoin":
            self.handle_namecoin()
            return
        if self.path == "/honeypot/fail":
            self._json(503, {"accepted": 0, "rejected": 1})
            return
        self._json(404, {"error": "not found"})

    def handle_hns(self):
        req = self._read_json()
        qname = str(req.get("qname", "")).lower().rstrip(".") + "."
        qtype = str(req.get("qtype", "A")).upper()
        if qname == "missing.hns.":
            self._json(200, {
                "source_plugin": "hns",
                "rcode": "NXDOMAIN",
                "ttl": 60,
                "rrset": [],
                "raw_record": {"backend": "docker-fixture-hns"},
                "audit_metadata": {"reason": "fixture_name_not_found"},
            })
            return
        records = {
            "example.hns.": [
                rr("example.hns.", "A", "198.51.100.53"),
                rr("example.hns.", "AAAA", "2001:db8::53"),
                rr("example.hns.", "TXT", "docker hns fixture"),
            ],
            "wallet.hns.": [
                rr("wallet.hns.", "WALLET", "eth 0x1111111111111111111111111111111111111111"),
                rr("wallet.hns.", "TYPE262", r"\# 23 036574682A307831313131313131313131313131313131313131313131313131313131313131313131"),
            ],
            "private.hns.": [
                rr("private.hns.", "A", "10.0.0.10"),
            ],
        }.get(qname, [])
        if qtype not in ("ANY", "*"):
            records = [record for record in records if record["type"] == qtype]
        self._json(200, {
            "source_plugin": "hns",
            "rcode": "NOERROR" if records else "NXDOMAIN",
            "ttl": 300 if records else 60,
            "rrset": records,
            "raw_record": {"backend": "docker-fixture-hns"},
            "audit_metadata": {"fixture": "hns-runtime-json"},
        })

    def handle_namecoin(self):
        req = self._read_json()
        params = req.get("params", [])
        name = params[0] if params else ""
        if name == "d/missing":
            self._json(200, {
                "result": None,
                "error": {"code": -4, "message": "name not found"},
                "id": req.get("id"),
            })
            return
        if name != "d/example":
            self._json(200, {
                "result": None,
                "error": {"code": -4, "message": "name not found"},
                "id": req.get("id"),
            })
            return
        value = {
            "ip": ["198.51.100.77", "2001:db8::77"],
            "ns": ["ns1.example.bit"],
            "txt": "docker namecoin fixture",
            "map": {
                "www": {
                    "ip": "198.51.100.78",
                    "info": "docker namecoin subdomain fixture"
                }
            }
        }
        self._json(200, {
            "result": {"name": "d/example", "value": json.dumps(value)},
            "error": None,
            "id": req.get("id"),
        })

    def handle_unstoppable(self):
        self._json(200, {
            "meta": {
                "domain": "alice.crypto",
                "type": "Uns"
            },
            "records": {
                "dns.A": "198.51.100.88",
                "dns.TXT": "docker unstoppable fixture",
                "browser.redirect_url": "https://alice.example.test",
                "ipfs.html.value": "bafybeigdyrzt",
                "crypto.ETH.address": "0x2222222222222222222222222222222222222222",
                "crypto.BTC.address": "bc1qdockerfixture"
            }
        })

    def handle_stacks_bns(self):
        zonefile = {
            "owner": "SP2DOCKERFIXTURE",
            "website": "alice.example.test",
            "btc": "bc1qstacksfixture",
            "addresses": [
                {
                    "network": "eth",
                    "address": "0x3333333333333333333333333333333333333333",
                    "type": "wallet"
                }
            ],
            "meta": [
                {
                    "name": "profile",
                    "value": "docker stacks fixture"
                }
            ]
        }
        self._json(200, {"zonefile": json.dumps(zonefile)})


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()

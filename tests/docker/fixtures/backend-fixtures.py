#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


ENS_RESOLVER_SELECTOR = "0178b8bf"
ENS_ADDR_SELECTOR = "3b3b57de"
ENS_TEXT_SELECTOR = "59d1d43c"
ENS_CONTENTHASH_SELECTOR = "bc1c58d1"


def rr(name, rrtype, value, ttl=300):
    return {"name": name, "type": rrtype, "ttl": ttl, "value": value}


def left_pad_hex(value, size):
    return str(value).rjust(size, "0")


def right_pad_hex(value, block_size):
    remainder = len(value) % block_size
    if remainder == 0:
        return value
    return value + ("0" * (block_size - remainder))


def abi_string_return(value):
    encoded = value.encode("utf-8").hex()
    return "0x" + left_pad_hex("20", 64) + left_pad_hex(format(len(value), "x"), 64) + right_pad_hex(encoded, 64)


def abi_bytes_return(value):
    encoded = bytes(value).hex()
    return "0x" + left_pad_hex("20", 64) + left_pad_hex(format(len(value), "x"), 64) + right_pad_hex(encoded, 64)


def abi_address_return(address):
    return "0x" + ("0" * 24) + address.lower().removeprefix("0x")


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
        if self.path == "/name/alice.dot":
            self.handle_pns_polkadot()
            return
        if self.path == "/name/missing.dot":
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
        if self.path == "/ethereum":
            self.handle_ens_json_rpc()
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

    def handle_ens_json_rpc(self):
        req = self._read_json()
        params = req.get("params", [])
        call = params[0] if params else {}
        data = str(call.get("data", "")).lower().removeprefix("0x")
        if data.startswith(ENS_RESOLVER_SELECTOR):
            result = abi_address_return("0x1234567890abcdef1234567890abcdef12345678")
        elif data.startswith(ENS_ADDR_SELECTOR):
            result = abi_address_return("0x4444444444444444444444444444444444444444")
        elif data.startswith(ENS_TEXT_SELECTOR):
            if "656d61696c" in data:
                result = abi_string_return("alice.eth@example.test")
            elif "75726c" in data:
                result = abi_string_return("https://alice.eth.example.test")
            else:
                result = abi_string_return("")
        elif data.startswith(ENS_CONTENTHASH_SELECTOR):
            result = abi_bytes_return([0xe3, 0x01, 0x01, 0x70])
        else:
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32602, "message": "unexpected eth_call data"},
            })
            return
        self._json(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": result,
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

    def handle_pns_polkadot(self):
        self._json(200, {
            "result": "ok",
            "data": {
                "name": "alice.dot",
                "records": {
                    "address": "15DOTDockerFixture",
                    "addresses": [
                        {
                            "network": "ksm",
                            "address": "KSMDockerFixture"
                        }
                    ],
                    "website": "alice.dot.example.test",
                    "ipfs": "bafybeigdotfixture",
                    "twitter": "@dotfixture",
                    "dns.A": "198.51.100.99",
                    "dns.TXT": "docker pns polkadot fixture"
                }
            }
        })


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()

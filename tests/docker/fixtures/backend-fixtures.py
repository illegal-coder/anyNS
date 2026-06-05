#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import parse_qs, urlparse


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
        parsed = urlparse(self.path)
        if parsed.path == "/getAddress":
            self.handle_space_id(parse_qs(parsed.query))
            return
        if parsed.path == "/api/v3/dns/records":
            self.handle_ton_dns(parse_qs(parsed.query))
            return
        if self.path == "/api/mainnet/v3/address/alice":
            self.handle_aptos_names()
            return
        if self.path == "/api/mainnet/v3/address/missing":
            self._json(404, {"message": "name not found"})
            return
        parsed = urlparse(self.path)
        if parsed.path == "/domain/resolve":
            self.handle_freename(parse_qs(parsed.query))
            return
        if parsed.path == "/openalias/txt":
            self.handle_openalias(parse_qs(parsed.query))
            return
        if self.path == "/handles/alice":
            self.handle_ada_handle()
            return
        if self.path == "/handles/missing":
            self._json(404, {"message": "handle not found"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/hns/resolve":
            self.handle_hns()
            return
        if self.path == "/did-bit/resolve":
            self.handle_did_bit()
            return
        if self.path == "/namecoin":
            self.handle_namecoin()
            return
        if self.path == "/ethereum":
            self.handle_ens_json_rpc()
            return
        if self.path == "/pulsechain":
            self.handle_pulsechain_json_rpc()
            return
        if self.path == "/rsk":
            self.handle_rsk_json_rpc()
            return
        if self.path == "/v1/chain/get_pub_address":
            self.handle_fio_chain()
            return
        if self.path == "/sui":
            self.handle_suins_json_rpc()
            return
        if self.path == "/solana":
            self.handle_solana_sns_json_rpc()
            return
        if self.path == "/graphql":
            self.handle_tezos_domains()
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
            "ds": [[12345, 13, 2, "ABCD1234"]],
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

    def handle_did_bit(self):
        req = self._read_json()
        qname = str(req.get("qname", "")).lower().rstrip(".") + "."
        qtype = str(req.get("qtype", "A")).upper()
        if qname == "missing.did.bit.":
            self._json(200, {
                "source_plugin": "did-bit",
                "rcode": "NXDOMAIN",
                "ttl": 60,
                "rrset": [],
                "raw_record": {"backend": "docker-fixture-did-bit"},
                "audit_metadata": {"reason": "fixture_name_not_found"},
            })
            return
        records = []
        if qname == "alice.did.bit.":
            records = [
                rr("alice.did.bit.", "TXT", "did=did:bit:alice"),
                rr("alice.did.bit.", "TXT", "profile=docker d.id fixture"),
                rr("alice.did.bit.", "URI", "https://alice.did.example.test"),
                rr("alice.did.bit.", "WALLET", "eth 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ]
        if qtype not in ("ANY", "*"):
            records = [record for record in records if record["type"] == qtype]
        self._json(200, {
            "source_plugin": "did-bit",
            "rcode": "NOERROR" if records else "NXDOMAIN",
            "ttl": 300 if records else 60,
            "rrset": records,
            "raw_record": {"backend": "docker-fixture-did-bit"},
            "audit_metadata": {"fixture": "did-bit-runtime-json"},
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

    def handle_space_id(self, query):
        domain = query.get("domain", [""])[0]
        if domain == "alice.bnb":
            self._json(200, {
                "address": "0x7777777777777777777777777777777777777777",
                "code": 0,
                "msg": "success"
            })
            return
        if domain == "missing.arb":
            self._json(200, {
                "address": "",
                "code": 1,
                "msg": "no address found"
            })
            return
        self._json(404, {"message": "domain not found"})

    def handle_solana_sns_json_rpc(self):
        req = self._read_json()
        method = req.get("method", "")
        params = req.get("params", [])
        domain = params[0] if params else ""
        if method != "sns_resolveDomain":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32601, "message": "unexpected Solana SNS method"},
            })
            return
        if domain == "alice.sol":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": "HKKp49qGWXd639QsuH7JiLijfVW5UtCVY4s1n2HANwEA",
            })
            return
        if domain == "missing.sol":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"value": ""},
            })
            return
        self._json(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "error": {"code": -32000, "message": "unexpected Solana SNS fixture domain"},
        })

    def handle_ton_dns(self, query):
        domain = query.get("domain", [""])[0]
        if domain == "alice.ton":
            self._json(200, {
                "records": [
                    {
                        "domain": "alice.ton",
                        "dns_wallet": "EQCDockerWallet",
                        "dns_site_adnl": "0123456789abcdef",
                        "dns_storage_bag_id": "dockerbagid",
                        "dns_next_resolver": "EQCDockerResolver",
                        "nft_item_address": "EQCDockerNFT",
                        "nft_item_owner": "EQCDockerOwner"
                    }
                ]
            })
            return
        if domain == "missing.ton":
            self._json(200, {"records": []})
            return
        self._json(404, {"message": "domain not found"})

    def handle_tezos_domains(self):
        req = self._read_json()
        variables = req.get("variables", {})
        domain = variables.get("name", "")
        if domain == "alice.tez":
            self._json(200, {
                "data": {
                    "domain": {
                        "name": "alice.tez",
                        "address": "tz1DockerWallet11111111111111111111111111",
                        "owner": "tz1DockerOwner111111111111111111111111111",
                        "data": [
                            {
                                "key": "website",
                                "rawValue": "alice.tez.example.test",
                                "value": "alice.tez.example.test"
                            },
                            {
                                "key": "email",
                                "rawValue": "alice.tez@example.test",
                                "value": "alice.tez@example.test"
                            },
                            {
                                "key": "dns.a",
                                "rawValue": "198.51.100.101",
                                "value": "198.51.100.101"
                            },
                            {
                                "key": "ipfs",
                                "rawValue": "bafybeigtezosfixture",
                                "value": "bafybeigtezosfixture"
                            }
                        ]
                    }
                }
            })
            return
        if domain == "missing.tez":
            self._json(200, {"data": {"domain": None}})
            return
        self._json(200, {"errors": [{"message": "unexpected Tezos fixture domain"}]})

    def handle_aptos_names(self):
        self._json(200, {
            "address": "0x8888888888888888888888888888888888888888"
        })

    def handle_suins_json_rpc(self):
        req = self._read_json()
        method = req.get("method", "")
        params = req.get("params", [])
        domain = params[0] if params else ""
        if method != "suix_resolveNameServiceAddress":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32601, "message": "unexpected SuiNS method"},
            })
            return
        if domain == "alice.sui":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": "0x9999999999999999999999999999999999999999",
            })
            return
        if domain == "missing.sui":
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": None,
            })
            return
        self._json(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "error": {"code": -32000, "message": "unexpected SuiNS fixture domain"},
        })

    def handle_freename(self, query):
        domain = query.get("q", [""])[0]
        if domain == "alice.fns":
            self._json(200, {
                "host": "alice.fns",
                "network": "POLYGON",
                "tld": "fns",
                "sld": "alice",
                "records": [
                    {
                        "key": "token.ETH.0",
                        "type": "ETH",
                        "value": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    },
                    {
                        "key": "token.BTC.0",
                        "type": "BTC",
                        "value": "bc1qfreenamefixture"
                    },
                    {
                        "key": "redirect.WEBSITE.0",
                        "type": "WEBSITE",
                        "value": "alice.fns.example.test"
                    },
                    {
                        "key": "record.TXT.0",
                        "type": "TXT",
                        "value": "docker freename fixture"
                    },
                    {
                        "key": "profile.OWNER.0",
                        "type": "OWNER",
                        "value": "Alice FNS"
                    },
                    {
                        "key": "content.ipfs.0",
                        "type": "IPFS",
                        "value": "bafybeigfreenamefixture"
                    }
                ]
            })
            return
        if domain == "missing.fns":
            self._json(200, {"host": "missing.fns", "records": []})
            return
        self._json(404, {"message": "domain not found"})

    def handle_fio_chain(self):
        req = self._read_json()
        fio_address = req.get("fio_address", "")
        chain_code = str(req.get("chain_code", "")).upper()
        token_code = str(req.get("token_code", "")).upper()
        if fio_address == "alice@safu" and chain_code == "ETH" and token_code == "USDT":
            self._json(200, {
                "public_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            })
            return
        if fio_address == "missing@safu":
            self._json(404, {"message": "Public address not found"})
            return
        self._json(400, {"error": "unexpected FIO fixture request"})

    def handle_openalias(self, query):
        name = query.get("name", [""])[0]
        rrtype = query.get("type", [""])[0].upper()
        if rrtype != "TXT":
            self._json(400, {"error": "unexpected OpenAlias fixture query type"})
            return
        if name == "alice.openalias":
            self._json(200, {
                "records": [
                    {
                        "type": "TXT",
                        "parts": [
                            "oa1:xmr recipient_address=46BeWrHpwXmHDpDEUmZBWZfoQpdc6HaERCNmx1pEYL2rAcuwufPN9rXHHtyUA4QVy66qeFQkn6sfK8aHYjA3jk3o1Bv16em; recipient_name=Alice OpenAlias; tx_description=Docker fixture; tx_payment_id=1234abcd;"
                        ]
                    },
                    {
                        "type": "TXT",
                        "value": "v=spf1 -all"
                    }
                ]
            })
            return
        if name == "missing.openalias":
            self._json(200, {"txt": ["v=spf1 -all"]})
            return
        self._json(404, {"message": "name not found"})

    def handle_ada_handle(self):
        self._json(200, {
            "handle": "alice",
            "address": "addr1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            "display_name": "Alice ADA",
            "description": "docker ada handle fixture",
            "website": "https://alice.ada.example.test",
            "image": "ipfs://bafybeiadafixture"
        })

    def handle_pulsechain_json_rpc(self):
        req = self._read_json()
        params = req.get("params", [])
        call = params[0] if params else {}
        data = str(call.get("data", "")).lower().removeprefix("0x")
        to = str(call.get("to", "")).lower()
        if data.startswith(ENS_RESOLVER_SELECTOR):
            if to != "0x1111111111111111111111111111111111111111":
                self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "error": {"code": -32602, "message": "unexpected registry target"},
                })
                return
            result = abi_address_return("0x5555555555555555555555555555555555555555")
        elif data.startswith(ENS_ADDR_SELECTOR):
            result = abi_address_return("0x6666666666666666666666666666666666666666")
        elif data.startswith(ENS_TEXT_SELECTOR):
            if "75726c" in data:
                result = abi_string_return("https://alice.pls.example.test")
            else:
                result = abi_string_return("")
        elif data.startswith(ENS_CONTENTHASH_SELECTOR):
            result = abi_bytes_return([0xe5, 0x01, 0x01, 0x70])
        else:
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32602, "message": "unexpected pulsechain eth_call data"},
            })
            return
        self._json(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": result,
        })

    def handle_rsk_json_rpc(self):
        req = self._read_json()
        params = req.get("params", [])
        call = params[0] if params else {}
        data = str(call.get("data", "")).lower().removeprefix("0x")
        to = str(call.get("to", "")).lower()
        if data.startswith(ENS_RESOLVER_SELECTOR):
            if to != "0x2222222222222222222222222222222222222222":
                self._json(200, {
                    "jsonrpc": "2.0",
                    "id": req.get("id"),
                    "error": {"code": -32602, "message": "unexpected RSK registry target"},
                })
                return
            result = abi_address_return("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        elif data.startswith(ENS_ADDR_SELECTOR):
            result = abi_address_return("0xcccccccccccccccccccccccccccccccccccccccc")
        elif data.startswith(ENS_TEXT_SELECTOR):
            if "75726c" in data:
                result = abi_string_return("https://alice.rsk.example.test")
            else:
                result = abi_string_return("")
        elif data.startswith(ENS_CONTENTHASH_SELECTOR):
            result = abi_bytes_return([0xe3, 0x01, 0x01, 0x70])
        else:
            self._json(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32602, "message": "unexpected rsk eth_call data"},
            })
            return
        self._json(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "result": result,
        })


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()

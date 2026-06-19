import assert from "node:assert/strict";
import test from "node:test";

import { parseSOAContent, soaPayloadFromEditor } from "./soa.js";

test("parses SOA wire content into editable fields", () => {
  assert.deepEqual(parseSOAContent("ns1.example. hostmaster.example. 42 3600 600 86400 300", 600), {
    primary_ns: "ns1.example.",
    hostmaster: "hostmaster.example.",
    serial: "42",
    ttl: "600",
    refresh: "3600",
    retry: "600",
    expire: "86400",
    minimum: "300",
  });
});

test("rejects malformed SOA content", () => {
  assert.equal(parseSOAContent("ns1.example. hostmaster.example."), null);
});

test("builds SOA update payload with blank serial as auto increment", () => {
  assert.deepEqual(soaPayloadFromEditor({
    primary_ns: " ns1.example. ",
    hostmaster: "hostmaster.example.",
    serial: "",
    ttl: "300",
    refresh: "7200",
    retry: "900",
    expire: "86400",
    minimum: "300",
  }), {
    primary_ns: "ns1.example.",
    hostmaster: "hostmaster.example.",
    serial: 0,
    ttl: 300,
    refresh: 7200,
    retry: 900,
    expire: 86400,
    minimum: 300,
  });
});

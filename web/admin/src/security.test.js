import assert from "node:assert/strict";
import test from "node:test";

import { normalizeDNSLogPlatformDomainList } from "./security.js";

test("normalizes DNSLog platform domains for the security editor", () => {
  assert.deepEqual(normalizeDNSLogPlatformDomainList(`
    Interactsh.COM.
    dnslog.例子
    interactsh.com
  `), ["interactsh.com", "dnslog.xn--fsqu00a"]);
});

test("drops empty and wildcard-like DNSLog platform editor rows", () => {
  assert.deepEqual(normalizeDNSLogPlatformDomainList(["", "*.interactsh.com", " safe.example. "]), ["safe.example"]);
});

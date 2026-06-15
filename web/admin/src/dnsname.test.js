import test from "node:test";
import assert from "node:assert/strict";

import { domainToASCII, ensureTrailingDot, normalizeZoneInput } from "./dnsname.js";

test("normalizes Unicode HNS names to their PowerDNS form", () => {
  const displayName = normalizeZoneInput(" 灵.HNS. ", "hns");
  assert.equal(displayName, "灵");
  assert.equal(domainToASCII(displayName), "xn--5nx");
  assert.equal(ensureTrailingDot(domainToASCII(displayName)), "xn--5nx.");
});

test("maps Unicode full stops before IDNA conversion", () => {
  const displayName = normalizeZoneInput("例子。测试", "dns");
  assert.equal(displayName, "例子.测试");
  assert.equal(domainToASCII(displayName), "xn--fsqu00a.xn--0zwm56d");
});

test("rejects malformed host names", () => {
  assert.equal(domainToASCII("bad name.example"), "");
});

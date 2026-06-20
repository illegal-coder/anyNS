import assert from "node:assert/strict";
import test from "node:test";
import {
  certificateInventorySummary,
  privateRootTrustSummary,
  shortFingerprint,
} from "./certificates.js";

test("certificate inventory summary groups lifecycle states", () => {
  assert.deepEqual(certificateInventorySummary([
    { status: "issued" },
    { status: "revoked" },
    { status: "failed" },
    { status: "pending" },
    { status: "validating" },
    { status: "finalizing" },
    { status: "unexpected" },
  ]), {
    total: 7,
    issued: 1,
    revoked: 1,
    failed: 1,
    pending: 3,
    other: 1,
  });
});

test("private root trust summary separates ACME from private root mode", () => {
  assert.equal(privateRootTrustSummary(null).mode, "acme");
  assert.equal(privateRootTrustSummary(null).label, "ACME / public WebPKI");

  const summary = privateRootTrustSummary({
    issuer_mode: "private-ca",
    subject: "CN=anyNS Private Root CA",
    sha256_fingerprint: "AA".repeat(32),
    root_key_present: true,
    root_key_mode: "0600",
    disabled: false,
    backup_status: { status: "current" },
  });
  assert.equal(summary.mode, "private-ca");
  assert.equal(summary.label, "Private root active");
  assert.equal(summary.backupStatus, "current");
  assert.equal(summary.keyStatus, "present 0600");
  assert.equal(summary.fingerprint, "AAAAAAAAAAAA...AAAAAAAA");
});

test("private root trust summary does not propagate sensitive-looking fields", () => {
  const summary = privateRootTrustSummary({
    issuer_mode: "private-ca",
    subject: "CN=anyNS Private Root CA",
    sha256_fingerprint: "BB".repeat(32),
    root_key_present: true,
    root_key_mode: "0600",
    pem: "-----BEGIN PRIVATE KEY-----",
    path: "/var/lib/anyns/certificates/private-ca/root-key.pem",
  });
  const body = JSON.stringify(summary);
  assert.equal(body.includes("PRIVATE KEY"), false);
  assert.equal(body.includes("/var/lib"), false);
});

test("short fingerprint strips separators and preserves useful edges", () => {
  assert.equal(shortFingerprint("aa:bb:cc:dd"), "AABBCCDD");
  assert.equal(shortFingerprint("AA".repeat(32)), "AAAAAAAAAAAA...AAAAAAAA");
});

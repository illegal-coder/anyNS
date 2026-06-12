import assert from "node:assert/strict";
import test from "node:test";
import { featureAccess, normalizeCapabilities, visibleNavigation } from "./capabilities.js";

const navigation = [
  { id: "overview" },
  { id: "powerdns" },
  { id: "plugins" },
];

test("missing capability endpoint exposes only the fallback overview", () => {
  const capabilities = normalizeCapabilities(null);
  assert.deepEqual(visibleNavigation(navigation, capabilities).map((item) => item.id), ["overview"]);
  assert.equal(featureAccess(capabilities, "overview").mode, "readonly");
  assert.equal(featureAccess(capabilities, "plugins").read, false);
});

test("read-only features remain visible while hidden features are removed", () => {
  const capabilities = normalizeCapabilities({
    features: {
      overview: { available: true, read: true, write: false, mode: "readonly" },
      powerdns: { available: true, read: true, write: false, mode: "readonly" },
      plugins: { available: true, read: false, write: false, mode: "hidden" },
    },
  });
  const items = visibleNavigation(navigation, capabilities);
  assert.deepEqual(items.map((item) => item.id), ["overview", "powerdns"]);
  assert.equal(items[1].access.write, false);
});

test("unknown capabilities default to hidden", () => {
  assert.deepEqual(featureAccess({}, "missing"), {
    available: false,
    read: false,
    write: false,
    mode: "hidden",
    reason: "capability_not_exposed",
    endpoints: [],
  });
});
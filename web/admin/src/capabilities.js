const hiddenCapability = Object.freeze({
  available: false,
  read: false,
  write: false,
  mode: "hidden",
  reason: "capability_not_exposed",
  endpoints: [],
});

const fallbackCapabilities = Object.freeze({
  overview: Object.freeze({
    available: true,
    read: true,
    write: false,
    mode: "readonly",
    reason: "capabilities_endpoint_unavailable",
    endpoints: ["GET /api/v1/dashboard"],
  }),
});

export function normalizeCapabilities(payload) {
  if (!payload?.features || typeof payload.features !== "object") {
    return fallbackCapabilities;
  }
  return Object.fromEntries(Object.entries(payload.features).map(([id, value]) => [id, {
    available: Boolean(value?.available),
    read: Boolean(value?.read),
    write: Boolean(value?.write),
    mode: typeof value?.mode === "string" ? value.mode : "hidden",
    reason: typeof value?.reason === "string" ? value.reason : "",
    endpoints: Array.isArray(value?.endpoints) ? value.endpoints : [],
  }]));
}

export function featureAccess(capabilities, id) {
  return capabilities?.[id] || hiddenCapability;
}

export function featureAccessWithFallback(capabilities, id, fallbackID) {
  if (capabilities && Object.hasOwn(capabilities, id)) {
    return featureAccess(capabilities, id);
  }
  return featureAccess(capabilities, fallbackID);
}

export function visibleNavigation(navigation, capabilities) {
  return navigation
    .map((item) => ({ ...item, access: featureAccess(capabilities, item.capability || item.id) }))
    .filter((item) => item.access.read);
}

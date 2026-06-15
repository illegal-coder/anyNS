export function normalizeZoneInput(value, mode) {
  let normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replaceAll("\u3002", ".")
    .replaceAll("\uff0e", ".")
    .replaceAll("\uff61", ".")
    .replace(/\s+/g, "");
  if (mode === "hns") normalized = normalized.replace(/\.(hns|hsd)\.?$/, "");
  return trimTrailingDot(normalized);
}

export function domainToASCII(value) {
  const normalized = trimTrailingDot(String(value || "").trim());
  if (!normalized) return "";
  try {
    return new URL(`http://${normalized}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function trimTrailingDot(value = "") {
  return String(value).replace(/\.+$/, "");
}

export function ensureTrailingDot(value = "") {
  const normalized = String(value).trim();
  return normalized ? `${trimTrailingDot(normalized)}.` : "";
}

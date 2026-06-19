export function parseSOAContent(content = "", ttl = 300) {
  const fields = String(content || "").trim().split(/\s+/).filter(Boolean);
  if (fields.length !== 7) return null;
  const [primaryNS, hostmaster, serial, refresh, retry, expire, minimum] = fields;
  return {
    primary_ns: primaryNS,
    hostmaster,
    serial: String(serial),
    ttl: String(ttl || 300),
    refresh: String(refresh),
    retry: String(retry),
    expire: String(expire),
    minimum: String(minimum),
  };
}

export function soaPayloadFromEditor(editor) {
  const numberValue = (value) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
  };
  return {
    primary_ns: String(editor?.primary_ns || "").trim(),
    hostmaster: String(editor?.hostmaster || "").trim(),
    serial: numberValue(editor?.serial),
    ttl: numberValue(editor?.ttl),
    refresh: numberValue(editor?.refresh),
    retry: numberValue(editor?.retry),
    expire: numberValue(editor?.expire),
    minimum: numberValue(editor?.minimum),
  };
}

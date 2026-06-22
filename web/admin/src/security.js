import { domainToASCII, trimTrailingDot } from "./dnsname.js";

export function normalizeDNSLogPlatformDomainList(value) {
  const rows = Array.isArray(value) ? value : String(value || "").split("\n");
  const seen = new Set();
  const normalized = [];
  for (const row of rows) {
    const ascii = domainToASCII(trimTrailingDot(String(row || "").trim()));
    if (!ascii || ascii.includes("*")) continue;
    if (seen.has(ascii)) continue;
    seen.add(ascii);
    normalized.push(ascii);
  }
  return normalized;
}

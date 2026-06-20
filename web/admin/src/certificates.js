export function shortFingerprint(value = "") {
  const normalized = String(value).replace(/[^a-fA-F0-9]/g, "").toUpperCase();
  if (normalized.length <= 16) return normalized || "-";
  return `${normalized.slice(0, 12)}...${normalized.slice(-8)}`;
}

export function certificateInventorySummary(jobs = []) {
  const counts = {
    total: jobs.length,
    issued: 0,
    revoked: 0,
    failed: 0,
    pending: 0,
    other: 0,
  };
  for (const job of jobs) {
    switch (job?.status) {
      case "issued":
        counts.issued += 1;
        break;
      case "revoked":
        counts.revoked += 1;
        break;
      case "failed":
        counts.failed += 1;
        break;
      case "pending":
      case "validating":
      case "finalizing":
        counts.pending += 1;
        break;
      default:
        counts.other += 1;
        break;
    }
  }
  return counts;
}

export function privateRootTrustSummary(metadata) {
  if (!metadata) {
    return {
      mode: "acme",
      label: "ACME / public WebPKI",
      tone: "blue",
      description: "Public trust mode. No private root CA is configured for this service.",
      fingerprint: "-",
      backupStatus: "not_applicable",
      keyStatus: "not_applicable",
      disabled: false,
    };
  }
  const backupStatus = metadata.backup_status?.status || "missing";
  return {
    mode: metadata.issuer_mode || "private-ca",
    label: metadata.disabled ? "Private root disabled" : "Private root active",
    tone: metadata.disabled ? "red" : "green",
    description: metadata.subject || "Private root CA",
    fingerprint: shortFingerprint(metadata.sha256_fingerprint),
    backupStatus,
    keyStatus: metadata.root_key_present ? `present ${metadata.root_key_mode || ""}`.trim() : "missing",
    disabled: Boolean(metadata.disabled),
  };
}

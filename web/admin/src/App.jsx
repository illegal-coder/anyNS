import { createElement, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  Blocks,
  BookOpenCheck,
  Check,
  ChevronRight,
  CircleAlert,
  Copy,
  Database,
  Edit3,
  FileClock,
  Gauge,
  Globe2,
  KeyRound,
  Layers3,
  LoaderCircle,
  LogOut,
  Menu,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ServerCog,
  Settings,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { api, getToken, setToken } from "./api";
import {
  certificateInventorySummary,
  privateRootTrustSummary,
  shortFingerprint,
} from "./certificates";
import {
  featureAccess,
  featureAccessWithFallback,
  normalizeCapabilities,
  visibleNavigation,
} from "./capabilities";
import { domainToASCII, ensureTrailingDot, normalizeZoneInput, trimTrailingDot } from "./dnsname";
import { parseSOAContent, soaPayloadFromEditor } from "./soa";

const navigation = [
  { id: "overview", capability: "overview", label: "总览", icon: Gauge },
  { id: "powerdns", capability: "powerdns", label: "PowerDNS", icon: Layers3 },
  { id: "certificates", capability: "certificates", label: "Certificates", icon: BookOpenCheck },
  { id: "plugins", capability: "plugins", label: "插件", icon: Blocks },
  { id: "security", capability: "security", label: "DNS 安全", icon: ShieldCheck },
  { id: "audit", capability: "audit", label: "审计日志", icon: FileClock },
  { id: "config", capability: "config", label: "配置", icon: Settings },
];

function App() {
  const [page, setPage] = useState("overview");
  const [capabilities, setCapabilities] = useState(() => normalizeCapabilities(null));
  const [dashboard, setDashboard] = useState(null);
  const [configuration, setConfiguration] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [authOpen, setAuthOpen] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const load = useCallback(async (quiet = false) => {
    quiet ? setRefreshing(true) : setLoading(true);
    setError("");
    try {
      const [capabilityPayload, data] = await Promise.all([
        api("/api/v1/capabilities").catch((capabilityError) => {
          if (capabilityError.status === 404) return null;
          throw capabilityError;
        }),
        api("/api/v1/dashboard?event_limit=50"),
      ]);
      setCapabilities(normalizeCapabilities(capabilityPayload));
      setDashboard(data);
      setConfiguration(data.configuration);
    } catch (loadError) {
      if (loadError.status === 401) {
        setAuthOpen(true);
      } else {
        setError(loadError.message);
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const navigationItems = useMemo(
    () => visibleNavigation(navigation, capabilities),
    [capabilities],
  );

  useEffect(() => {
    if (!navigationItems.some((item) => item.id === page)) {
      setPage(navigationItems[0]?.id || "overview");
    }
  }, [navigationItems, page]);

  const mutate = async (action, message) => {
    setError("");
    try {
      await action();
      setNotice(message);
      await load(true);
    } catch (mutationError) {
      if (mutationError.status === 401) setAuthOpen(true);
      setError(mutationError.message);
    }
  };

  const saveConfiguration = async (next) => {
    await mutate(async () => {
      const result = await api("/api/v1/configuration", {
        method: "PUT",
        body: JSON.stringify(next),
      });
      setConfiguration(result.configuration);
    }, "配置已保存并触发运行时重载");
  };

  const activeItem = navigationItems.find((item) => item.id === page);
  const contentProps = {
    dashboard,
    configuration,
    setConfiguration,
    mutate,
    load,
    saveConfiguration,
    capabilities,
  };

  return (
    <div className="app-shell">
      <Sidebar
        items={navigationItems}
        page={page}
        setPage={setPage}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      <main className="main-area">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="打开导航">
            <Menu size={20} />
          </button>
          <div>
            <span className="eyebrow">测试环境</span>
            <h1>{activeItem?.label}</h1>
          </div>
          <div className="topbar-actions">
            <ConnectionBadge dashboard={dashboard} />
            <button className="button secondary" onClick={() => load(true)} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? "spin" : ""} />
              刷新
            </button>
            <button className="icon-button" onClick={() => setAuthOpen(true)} title="管理令牌">
              <KeyRound size={18} />
            </button>
          </div>
        </header>

        {notice && <Toast type="success" message={notice} onClose={() => setNotice("")} />}
        {error && <Toast type="error" message={error} onClose={() => setError("")} />}

        <section className="content">
          {loading ? (
            <LoadingState />
          ) : (
            <>
              {page === "overview" && <Overview {...contentProps} setPage={setPage} />}
              {page === "powerdns" && <PowerDNSPage {...contentProps} />}
              {page === "certificates" && <CertificatesPage {...contentProps} />}
              {page === "plugins" && <PluginsPage {...contentProps} />}
              {page === "security" && <SecurityPage {...contentProps} />}
              {page === "audit" && <AuditPage {...contentProps} />}
              {page === "config" && <ConfigurationPage {...contentProps} />}
            </>
          )}
        </section>
      </main>
      {authOpen && <AuthDialog onClose={() => setAuthOpen(false)} onSaved={() => load()} />}
    </div>
  );
}

function Sidebar({ items, page, setPage, open, onClose }) {
  return (
    <>
      {open && <button className="sidebar-scrim" onClick={onClose} aria-label="关闭导航" />}
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Network size={23} /></div>
          <div><strong>anyNS</strong><span>Control Plane</span></div>
        </div>
        <nav>
          {items.map(({ id, label, icon, access }) => (
            <button
              key={id}
              className={[
                page === id ? "active" : "",
                access.mode === "readonly" ? "nav-readonly" : "",
                access.mode === "unavailable" ? "nav-unavailable" : "",
              ].filter(Boolean).join(" ")}
              onClick={() => { setPage(id); onClose(); }}
              title={access.mode === "readwrite" ? label : `${label}：${access.mode === "unavailable" ? "后端未配置" : "只读"}`}
            >
              {createElement(icon, { size: 19 })}
              <span>{label}</span>
              {access.mode !== "readwrite" && <small className="nav-mode">{access.mode === "unavailable" ? "未配置" : "只读"}</small>}
              {id === "powerdns" && <ChevronRight size={15} className="nav-chevron" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <BookOpenCheck size={17} />
          <span>API v1</span>
        </div>
      </aside>
    </>
  );
}

function Overview({ dashboard, mutate, setPage, capabilities }) {
  const canFlushCache = featureAccess(capabilities, "cache").write;
  const canReloadPolicy = featureAccess(capabilities, "policy").write;
  const canReadAudit = featureAccess(capabilities, "audit").read;
  const canReadPowerDNS = featureAccess(capabilities, "powerdns").read;
  const canReadPlugins = featureAccess(capabilities, "plugins").read;
  const powerdns = dashboard?.services?.powerdns || {};
  const events = dashboard?.recent_events || [];
  const plugins = dashboard?.plugins || [];
  const zones = powerdns.authoritative?.zones || [];

  return (
    <div className="page-stack">
      <div className="page-actions">
        <div>
          <p className="section-kicker">CONTROL PLANE</p>
          <h2>DNS 服务运行概览</h2>
          <p>统一查看 PowerDNS、anyNS 插件和安全策略的实时状态。</p>
        </div>
        <div className="action-row">
          <button className="button secondary" disabled={!canFlushCache} onClick={() => mutate(
            () => api("/api/v1/cache/flush", { method: "POST" }),
            "anyNS 插件缓存已清理",
          )}><RotateCcw size={16} />清理插件缓存</button>
          <button className="button primary" disabled={!canReloadPolicy} onClick={() => mutate(
            () => api("/api/v1/policies/reload", { method: "POST" }),
            "策略已重新加载",
          )}><RefreshCw size={16} />重新加载策略</button>
        </div>
      </div>

      <ServiceStrip dashboard={dashboard} />

      <div className="overview-grid">
        <Panel
          className="traffic-panel"
          title="DNS 请求活动"
          subtitle={`当前缓冲 ${dashboard?.audit_summary?.total || 0} 条事件`}
          action={canReadAudit ? <button className="text-button" onClick={() => setPage("audit")}>查看全部</button> : null}
        >
          <TrafficChart events={events} />
        </Panel>
        <Panel title="近期安全事件" subtitle="按时间倒序" action={canReadAudit ? <button className="text-button" onClick={() => setPage("audit")}>查看全部</button> : null}>
          <EventList events={events.slice(0, 7)} />
        </Panel>
        <Panel title="PowerDNS Zones" subtitle={`${zones.length} 个权威区域`} action={canReadPowerDNS ? <button className="text-button" onClick={() => setPage("powerdns")}>管理区域</button> : null}>
          <ZoneTable zones={zones.slice(0, 6)} compact />
        </Panel>
        <Panel title="anyNS 插件" subtitle={`${plugins.filter((item) => item.enabled).length}/${plugins.length} 已启用`} action={canReadPlugins ? <button className="text-button" onClick={() => setPage("plugins")}>管理插件</button> : null}>
          <PluginTable plugins={plugins.slice(0, 7)} compact />
        </Panel>
      </div>
    </div>
  );
}

function ServiceStrip({ dashboard }) {
  const powerdns = dashboard?.services?.powerdns || {};
  const runtime = dashboard?.services?.runtime || {};
  const services = [
    {
      name: "Authoritative",
      detail: powerdns.authoritative?.server
        ? `PowerDNS ${powerdns.authoritative.server.version || ""}`
        : "PowerDNS 权威服务",
      healthy: powerdns.authoritative?.healthy,
      configured: powerdns.authoritative?.configured,
      metric: `${powerdns.authoritative?.zones?.length || 0} Zones`,
      icon: Database,
      tone: "orange",
    },
    {
      name: "Recursor",
      detail: powerdns.recursor?.server
        ? `PowerDNS ${powerdns.recursor.server.version || ""}`
        : "PowerDNS 递归服务",
      healthy: powerdns.recursor?.healthy,
      configured: powerdns.recursor?.configured,
      metric: statValue(powerdns.recursor?.statistics, ["cache-hits", "packetcache-hits"]) || "API",
      icon: Activity,
      tone: "purple",
    },
    {
      name: "anyNS Runtime",
      detail: "去中心化域名与安全运行时",
      healthy: runtime.healthy,
      configured: runtime.configured,
      metric: `${dashboard?.plugins?.filter((item) => item.enabled).length || 0} 插件`,
      icon: Network,
      tone: "cyan",
    },
    {
      name: "Admin API",
      detail: "统一 Web 管理接口",
      healthy: true,
      configured: true,
      metric: `${dashboard?.audit_summary?.total || 0} 事件`,
      icon: ServerCog,
      tone: "blue",
    },
  ];
  return (
    <div className="service-strip">
      {services.map((service) => {
        const Icon = service.icon;
        return (
          <div className="service-item" key={service.name}>
            <div className={`service-icon ${service.tone}`}><Icon size={22} /></div>
            <div className="service-copy">
              <div><strong>{service.name}</strong><StatusPill healthy={service.healthy} configured={service.configured} /></div>
              <span>{service.detail}</span>
            </div>
            <b>{service.metric}</b>
          </div>
        );
      })}
    </div>
  );
}

function CertificatesPage({ mutate, capabilities }) {
  const access = featureAccess(capabilities, "certificates");
  const [jobs, setJobs] = useState([]);
  const [privateRoot, setPrivateRoot] = useState(null);
  const [domains, setDomains] = useState("");
  const [loadingJobs, setLoadingJobs] = useState(true);
  const [loadingRoot, setLoadingRoot] = useState(true);
  const [jobsError, setJobsError] = useState("");
  const [rootError, setRootError] = useState("");

  const loadJobs = useCallback(async () => {
    setLoadingJobs(true);
    try {
      setJobs(await api("/api/v1/certificates/orders"));
      setJobsError("");
    } catch (loadError) {
      setJobsError(loadError.message);
    } finally {
      setLoadingJobs(false);
    }
  }, []);

  const loadPrivateRoot = useCallback(async () => {
    setLoadingRoot(true);
    try {
      setPrivateRoot(await api("/api/v1/certificates/private-ca/root"));
      setRootError("");
    } catch (loadError) {
      if (loadError.status === 404) {
        setPrivateRoot(null);
        setRootError("");
      } else {
        setRootError(loadError.message);
      }
    } finally {
      setLoadingRoot(false);
    }
  }, []);

  useEffect(() => {
    if (!access.available || !access.read) {
      setLoadingJobs(false);
      setLoadingRoot(false);
      return undefined;
    }
    void loadJobs();
    void loadPrivateRoot();
    const timer = window.setInterval(() => {
      void loadJobs();
      void loadPrivateRoot();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [access.available, access.read, loadJobs, loadPrivateRoot]);

  const issue = async () => {
    const requestedDomains = domains.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);
    await mutate(
      () => api("/api/v1/certificates/orders", {
        method: "POST",
        body: JSON.stringify({
          domains: requestedDomains,
          idempotency_key: `ui-${Date.now()}-${requestedDomains.join(",")}`,
        }),
      }),
      "Certificate order accepted",
    );
    setDomains("");
    await loadJobs();
  };

  const inventory = certificateInventorySummary(jobs);
  const trust = privateRootTrustSummary(privateRoot);

  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">ACME / Private CA</p><h2>Certificate issuance</h2><p>Private keys remain in server-side storage and are never returned by this console.</p></div>
      </div>
      {access.mode !== "readwrite" && <InlineWarning text={access.available ? "Current credentials are read-only." : "Certificate issuance is not configured."} />}
      {jobsError && <InlineWarning text={`Certificate orders could not be loaded: ${jobsError}`} />}
      {rootError && <InlineWarning text={`Private root metadata could not be loaded: ${rootError}`} />}
      <Panel title="Trust root" subtitle="ACME and private-root trust are shown as separate modes">
        {loadingRoot ? <LoadingState /> : (
          <div className="certificate-summary">
            <div>
              <span>Mode</span>
              <strong><span className={`tag ${trust.tone}`}>{trust.label}</span></strong>
              <small>{trust.description}</small>
            </div>
            <div>
              <span>Root fingerprint</span>
              <strong className="mono">{trust.fingerprint}</strong>
              <small>{privateRoot?.serial_number ? `Serial ${privateRoot.serial_number}` : "No private root fingerprint in ACME mode"}</small>
            </div>
            <div>
              <span>Backup status</span>
              <strong>{trust.backupStatus}</strong>
              <small>{privateRoot?.backup_status?.recorded_at ? new Date(privateRoot.backup_status.recorded_at).toLocaleString() : "No backup timestamp"}</small>
            </div>
            <div>
              <span>Root key</span>
              <strong>{trust.keyStatus}</strong>
              <small>Key material and storage paths are never displayed.</small>
            </div>
          </div>
        )}
      </Panel>
      <Panel title="New certificate order" subtitle="Use public DNS names delegated to the configured PowerDNS authoritative service">
        <fieldset className="readonly-fieldset" disabled={!access.write}>
          <div className="form-grid single">
            <Field label="DNS names">
              <textarea value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="example.org, www.example.org" />
            </Field>
            <button className="button primary" disabled={!domains.trim()} onClick={issue}><Plus size={16} />Issue certificate</button>
          </div>
        </fieldset>
      </Panel>
      <Panel title="Certificate orders" subtitle={`${inventory.total} persisted jobs: ${inventory.issued} issued, ${inventory.revoked} revoked, ${inventory.failed} failed, ${inventory.pending} active`}>
        {loadingJobs ? <LoadingState /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Domains</th><th>Status</th><th>Attempts</th><th>Expires</th><th>Renewal</th><th>Error</th></tr></thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job.id}>
                    <td><code>{job.id}</code></td>
                    <td>{job.domains?.join(", ")}</td>
                    <td>{job.status}</td>
                    <td>{job.attempt}/{job.max_attempts}</td>
                    <td>{job.not_after ? new Date(job.not_after).toLocaleString() : "-"}</td>
                    <td>{job.renewal_of ? <code>{shortFingerprint(job.renewal_of)}</code> : "-"}</td>
                    <td className="muted">{job.error || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!jobs.length && <EmptyState text="No certificate orders" />}
          </div>
        )}
      </Panel>
    </div>
  );
}

const recordTypes = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA", "PTR", "DS", "DNSKEY", "SVCB", "HTTPS", "TLSA"];
const defaultRecordEditor = { name: "@", type: "A", ttl: "300", content: "", originalName: "", originalType: "" };
const defaultSOA = { hostmaster: "", ttl: "300", refresh: "3600", retry: "600", expire: "86400", minimum: "300" };
const authoritativeIPv4Example = "192.0.2.53";

function PowerDNSPage({ dashboard, mutate, capabilities }) {
  const access = featureAccess(capabilities, "powerdns");
  const authoritativeAccess = featureAccessWithFallback(capabilities, "powerdns_authoritative", "powerdns");
  const recursorAccess = featureAccessWithFallback(capabilities, "powerdns_recursor", "powerdns");
  const canWriteAuthoritative = authoritativeAccess.available && authoritativeAccess.write;
  const canFlushRecursor = recursorAccess.available && recursorAccess.write;
  const snapshot = dashboard?.services?.powerdns || {};
  const zones = snapshot.authoritative?.zones || [];
  const [zoneMode, setZoneMode] = useState("hns");
  const [zoneName, setZoneName] = useState("");
  const [nameserver, setNameserver] = useState("");
  const [glueIPv4, setGlueIPv4] = useState("");
  const [glueIPv6, setGlueIPv6] = useState("");
  const [soa, setSOA] = useState(defaultSOA);
  const [flushDomain, setFlushDomain] = useState("");
  const [selectedZoneID, setSelectedZoneID] = useState("");
  const [zoneDetail, setZoneDetail] = useState(null);
  const [cryptoKeys, setCryptoKeys] = useState([]);
  const [zoneLoading, setZoneLoading] = useState(false);
  const [recordQuery, setRecordQuery] = useState("");
  const [recordType, setRecordType] = useState("ALL");
  const [recordEditor, setRecordEditor] = useState(defaultRecordEditor);

  const normalizedZoneName = normalizeZoneInput(zoneName, zoneMode);
  const punycodeZoneName = domainToASCII(normalizedZoneName);
  const suggestedNameserver = punycodeZoneName ? `ns1.${punycodeZoneName}.` : "";
  const suggestedHostmaster = punycodeZoneName ? `hostmaster.${punycodeZoneName}.` : "";

  const loadZone = useCallback(async (zoneID) => {
    if (!zoneID) return;
    setZoneLoading(true);
    try {
      const [detail, keys] = await Promise.all([
        api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(zoneID)}`),
        api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(zoneID)}/cryptokeys`).catch(() => []),
      ]);
      setZoneDetail(detail);
      setCryptoKeys(keys);
    } finally {
      setZoneLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedZoneID) loadZone(selectedZoneID);
  }, [loadZone, selectedZoneID]);

  const createZone = () => mutate(async () => {
    const effectiveNameserver = nameserver.trim() || suggestedNameserver;
    const zone = await api("/api/v1/powerdns/authoritative/zones", {
      method: "POST",
      body: JSON.stringify({
        name: normalizedZoneName,
        kind: "Native",
        hns: zoneMode === "hns",
        nameservers: effectiveNameserver ? [ensureTrailingDot(effectiveNameserver)] : [],
        glue_ipv4: zoneMode === "hns" ? glueIPv4.trim() : "",
        glue_ipv6: zoneMode === "hns" ? glueIPv6.trim() : "",
        soa: {
          primary_ns: ensureTrailingDot(effectiveNameserver),
          hostmaster: ensureTrailingDot(soa.hostmaster.trim() || suggestedHostmaster),
          ttl: Number(soa.ttl) || 300,
          refresh: Number(soa.refresh) || 3600,
          retry: Number(soa.retry) || 600,
          expire: Number(soa.expire) || 86400,
          minimum: Number(soa.minimum) || 300,
        },
      }),
    });
    setSelectedZoneID(zone.id || zone.name);
    setZoneName("");
    setNameserver("");
    setGlueIPv6("");
    setSOA(defaultSOA);
  }, `Zone ${normalizedZoneName}（${punycodeZoneName}）已创建`);

  const patchRRSet = async (rrset, message) => {
    await mutate(
      () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(selectedZoneID)}/rrsets`, {
        method: "PATCH",
        body: JSON.stringify({ rrsets: [rrset] }),
      }),
      message,
    );
    await loadZone(selectedZoneID);
  };

  const saveRecord = async () => {
    const zone = zoneDetail?.name || selectedZoneID;
    const name = absoluteRecordName(recordEditor.name, zone);
    const records = recordEditor.content
      .split("\n")
      .map((content) => formatRecordContent(recordEditor.type, content))
      .filter(Boolean)
      .map((content) => ({ content, disabled: false }));
    if (recordEditor.originalName && (
      recordEditor.originalName !== name ||
      recordEditor.originalType !== recordEditor.type
    )) {
      await patchRRSet({
        name: recordEditor.originalName,
        type: recordEditor.originalType,
        changetype: "DELETE",
      }, "原记录集已移除");
    }
    await patchRRSet({
      name,
      type: recordEditor.type,
      ttl: Number(recordEditor.ttl) || 300,
      changetype: "REPLACE",
      records,
    }, `${recordEditor.type} 记录已保存`);
    setRecordEditor(defaultRecordEditor);
  };

  const visibleRRSets = useMemo(() => {
    const query = recordQuery.trim().toLowerCase();
    return (zoneDetail?.rrsets || []).filter((rrset) => {
      if (recordType !== "ALL" && rrset.type !== recordType) return false;
      if (!query) return true;
      return [rrset.name, rrset.type, ...(rrset.records || []).map((record) => record.content)]
        .some((value) => String(value || "").toLowerCase().includes(query));
    });
  }, [recordQuery, recordType, zoneDetail]);

  if (selectedZoneID) {
    return (
      <ZoneWorkspace
        zone={zoneDetail}
        cryptoKeys={cryptoKeys}
        loading={zoneLoading}
        canWrite={canWriteAuthoritative}
        recordQuery={recordQuery}
        setRecordQuery={setRecordQuery}
        recordType={recordType}
        setRecordType={setRecordType}
        rrsets={visibleRRSets}
        editor={recordEditor}
        setEditor={setRecordEditor}
        onSave={saveRecord}
        onCreateCryptoKey={() => mutate(
          () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(selectedZoneID)}/cryptokeys`, {
            method: "POST",
            body: JSON.stringify({ keytype: "csk", active: true, published: true }),
          }),
          "DNSSEC CSK created",
        ).then(() => loadZone(selectedZoneID))}
        onDeleteCryptoKey={(keyID) => mutate(
          () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(selectedZoneID)}/cryptokeys/${keyID}`, { method: "DELETE" }),
          "DNSSEC key deleted",
        ).then(() => loadZone(selectedZoneID))}
        onSaveSOA={(payload) => mutate(
          () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(selectedZoneID)}/soa`, {
            method: "PATCH",
            body: JSON.stringify(payload),
          }),
          "SOA 与 serial 已更新",
        ).then(() => loadZone(selectedZoneID))}
        onDelete={(rrset) => patchRRSet({
          name: rrset.name,
          type: rrset.type,
          changetype: "DELETE",
        }, `${rrset.type} 记录已删除`)}
        onBack={() => {
          setSelectedZoneID("");
          setZoneDetail(null);
          setCryptoKeys([]);
          setRecordEditor(defaultRecordEditor);
        }}
      />
    );
  }

  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">POWERDNS</p><h2>权威与递归服务</h2><p>API 密钥仅由 anyNS 后端持有，浏览器不直接连接 PowerDNS。</p></div>
      </div>
      {access.mode !== "readwrite" && <InlineWarning text={access.available ? "当前凭据仅允许读取 PowerDNS。" : "PowerDNS 后端尚未配置，页面为只读状态。"} />}
      <div className="split-status">        <PowerDNSService service={snapshot.authoritative} title="Authoritative" />
        <PowerDNSService service={snapshot.recursor} title="Recursor" />
      </div>
      <div className="dns-zone-layout">
        <Panel title="托管域名" subtitle={`${zones.length} 个权威 Zone`}>
          <ZoneTable
            zones={zones}
            onSelect={(zone) => setSelectedZoneID(zone.id || zone.name)}
            onDelete={canWriteAuthoritative ? (zone) => mutate(
              () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(zone.id)}`, { method: "DELETE" }),
              `Zone ${zone.name} 已删除`,
            ) : undefined}
          />
        </Panel>
        <div className="form-stack">
          <Panel title="添加托管域名" subtitle="创建权威 Zone 并准备 HNS 委派">
            {!authoritativeAccess.available && <InlineWarning text="PowerDNS Authoritative 后端尚未配置，无法创建或管理 Zone。" />}
            <fieldset className="readonly-fieldset" disabled={!canWriteAuthoritative}>
            <div className="form-grid single">
              <div className="segmented-control" aria-label="域名类型">
                <button type="button" className={zoneMode === "hns" ? "active" : ""} onClick={() => setZoneMode("hns")}>HNS 域名</button>
                <button type="button" className={zoneMode === "dns" ? "active" : ""} onClick={() => setZoneMode("dns")}>传统 DNS</button>
              </div>
              <Field label={zoneMode === "hns" ? "HNS 名称" : "Zone 名称"}>
                <input
                  value={zoneName}
                  onChange={(event) => setZoneName(event.target.value)}
                  placeholder={zoneMode === "hns" ? "灵 或 example（可填写中文，不要填写 .hns）" : "例子.测试 或 example.org"}
                />
              </Field>
              {normalizedZoneName && (
                <div className={`idna-preview ${punycodeZoneName ? "" : "invalid"}`}>
                  <span>显示名称 <strong>{normalizedZoneName}</strong></span>
                  <span>PowerDNS / HNS Punycode <code>{punycodeZoneName || "名称格式无效"}</code></span>
                </div>
              )}
              <Field label="初始 Nameserver">
                <input
                  value={nameserver}
                  onChange={(event) => setNameserver(event.target.value)}
                  placeholder={suggestedNameserver || "ns1.example."}
                />
              </Field>
              {zoneMode === "hns" && (
                <Field label="Glue IPv4">
                  <input value={glueIPv4} onChange={(event) => setGlueIPv4(event.target.value)} placeholder={authoritativeIPv4Example} />
                </Field>
              )}
              {zoneMode === "hns" && (
                <Field label="Glue IPv6（可选）">
                  <input value={glueIPv6} onChange={(event) => setGlueIPv6(event.target.value)} placeholder="2001:db8::53" />
                </Field>
              )}
              <details className="advanced-settings">
                <summary>SOA 高级设置</summary>
                <div className="advanced-settings-grid">
                  <Field label="Hostmaster">
                    <input value={soa.hostmaster} onChange={(event) => setSOA({ ...soa, hostmaster: event.target.value })} placeholder={suggestedHostmaster || "hostmaster.example."} />
                  </Field>
                  <Field label="SOA TTL">
                    <input type="number" min="60" value={soa.ttl} onChange={(event) => setSOA({ ...soa, ttl: event.target.value })} />
                  </Field>
                  <Field label="Refresh">
                    <input type="number" min="60" value={soa.refresh} onChange={(event) => setSOA({ ...soa, refresh: event.target.value })} />
                  </Field>
                  <Field label="Retry">
                    <input type="number" min="60" value={soa.retry} onChange={(event) => setSOA({ ...soa, retry: event.target.value })} />
                  </Field>
                  <Field label="Expire">
                    <input type="number" min="300" value={soa.expire} onChange={(event) => setSOA({ ...soa, expire: event.target.value })} />
                  </Field>
                  <Field label="Negative TTL">
                    <input type="number" min="60" value={soa.minimum} onChange={(event) => setSOA({ ...soa, minimum: event.target.value })} />
                  </Field>
                </div>
              </details>
              {zoneMode === "hns" && <p className="form-help">将创建 <code>{punycodeZoneName ? `${punycodeZoneName}.` : "example."}</code>，并原子写入 SOA、NS 和 Glue。HNS 链上仍需发布相同的 NS/GLUE4/GLUE6。</p>}
              <button
                className="button primary"
                disabled={!punycodeZoneName || (zoneMode === "hns" && !glueIPv4.trim() && !glueIPv6.trim())}
                onClick={createZone}
              ><Plus size={16} />添加域名</button>
            </div>
            </fieldset>
          </Panel>
          <Panel title="清理 Recursor 缓存" subtitle="支持单域名或子树缓存">
            {!recursorAccess.available && <InlineWarning text="PowerDNS Recursor 后端尚未配置，无法清理缓存。" />}
            <fieldset className="readonly-fieldset" disabled={!canFlushRecursor}>
            <div className="form-grid single">
              <Field label="域名（留空表示全部）">
                <input value={flushDomain} onChange={(event) => setFlushDomain(event.target.value)} placeholder="example.org" />
              </Field>
              <button className="button secondary" disabled={!canFlushRecursor} onClick={() => mutate(
                () => api("/api/v1/powerdns/recursor/cache/flush", {
                  method: "POST",
                  body: JSON.stringify({ domain: flushDomain, subtree: true }),
                }),
                "Recursor 缓存已清理",
              )}><RotateCcw size={16} />清理缓存子树</button>
            </div>
            </fieldset>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ZoneWorkspace({
  zone,
  cryptoKeys,
  loading,
  canWrite,
  recordQuery,
  setRecordQuery,
  recordType,
  setRecordType,
  rrsets,
  editor,
  setEditor,
  onSave,
  onCreateCryptoKey,
  onDeleteCryptoKey,
  onSaveSOA,
  onDelete,
  onBack,
}) {
  const zoneName = zone?.name || "";
  const displayZoneName = zone?.unicode_name || zoneName;
  const hnsZone = isHNSZoneName(zoneName);
  const editing = Boolean(editor.originalName);
  const defaultNameserver = `ns1.${zoneName}`;
  const glueIPv4 = (zone?.rrsets || [])
    .find((rrset) => rrset.type === "A" && rrset.name === defaultNameserver)
    ?.records?.find((record) => !record.disabled)?.content || "";
  const soaRRSet = useMemo(
    () => (zone?.rrsets || []).find((rrset) => rrset.type === "SOA" && rrset.name === zoneName),
    [zone, zoneName],
  );
  const soaContent = soaRRSet?.records?.find((record) => !record.disabled)?.content || "";
  const parsedSOA = useMemo(() => parseSOAContent(soaContent, soaRRSet?.ttl), [soaContent, soaRRSet?.ttl]);
  const [soaEditor, setSOAEditor] = useState(null);

  useEffect(() => {
    setSOAEditor(parsedSOA ? { ...parsedSOA, serial: "" } : null);
  }, [parsedSOA]);

  const updateSOAField = (name, value) => setSOAEditor((current) => ({ ...current, [name]: value }));

  return (
    <div className="page-stack">
      <div className="zone-workspace-head">
        <button className="icon-button" onClick={onBack} aria-label="返回域名列表"><ArrowLeft size={18} /></button>
        <div className="zone-identity">
          <div className="zone-icon"><Globe2 size={21} /></div>
          <div><h2>{displayZoneName || "加载 Zone"}</h2><p>{displayZoneName !== zoneName ? `Punycode ${zoneName} · ` : ""}权威 DNS 记录与 HNS 委派管理</p></div>
        </div>
        <div className="zone-meta">
          <span>Serial <b>{zone?.serial || "-"}</b></span>
          <span>DNSSEC <b>{zone?.dnssec ? "已启用" : "未启用"}</b></span>
        </div>
      </div>

      <div className="hns-delegation">
        <div>
          <strong>{hnsZone ? "HNS 链上委派" : "权威 DNS 委派"}</strong>
          <span>{hnsZone
            ? "在钱包中为名称发布以下资源。网页负责托管记录，链上资源负责把请求交给本服务器。"
            : "在域名注册商或上级 DNS 中设置以下 NS；使用同域 Nameserver 时还需要 Glue 记录。"}</span>
        </div>
        <DelegationValue label="NS" value={defaultNameserver} />
        <DelegationValue label="GLUE4" value={glueIPv4 ? `${defaultNameserver} ${glueIPv4}` : "未找到 ns1 A Glue 记录"} />
        <div className="delegation-test"><code>{hnsZone ? `${trimTrailingDot(displayZoneName)}.hns` : trimTrailingDot(displayZoneName)}</code><span>{hnsZone ? "通过私有 DoH 验证" : "通过权威 DNS 验证"}</span></div>
      </div>

      <Panel title="SOA 与 Serial" subtitle="留空 serial 时自动递增；显式 serial 必须大于当前值">
        {soaEditor ? (
          <fieldset className="readonly-fieldset" disabled={!canWrite}>
            <div className="form-grid">
              <Field label="Primary NS">
                <input value={soaEditor.primary_ns} onChange={(event) => updateSOAField("primary_ns", event.target.value)} />
              </Field>
              <Field label="Hostmaster">
                <input value={soaEditor.hostmaster} onChange={(event) => updateSOAField("hostmaster", event.target.value)} />
              </Field>
              <Field label={`Serial（当前 ${parsedSOA?.serial || "-"}）`}>
                <input type="number" min={Number(parsedSOA?.serial || 0) + 1} value={soaEditor.serial} onChange={(event) => updateSOAField("serial", event.target.value)} placeholder="自动递增" />
              </Field>
              <Field label="SOA TTL">
                <input type="number" min="60" value={soaEditor.ttl} onChange={(event) => updateSOAField("ttl", event.target.value)} />
              </Field>
              <Field label="Refresh">
                <input type="number" min="60" value={soaEditor.refresh} onChange={(event) => updateSOAField("refresh", event.target.value)} />
              </Field>
              <Field label="Retry">
                <input type="number" min="60" value={soaEditor.retry} onChange={(event) => updateSOAField("retry", event.target.value)} />
              </Field>
              <Field label="Expire">
                <input type="number" min="300" value={soaEditor.expire} onChange={(event) => updateSOAField("expire", event.target.value)} />
              </Field>
              <Field label="Negative TTL">
                <input type="number" min="60" value={soaEditor.minimum} onChange={(event) => updateSOAField("minimum", event.target.value)} />
              </Field>
            </div>
            <div className="record-editor-actions">
              <button className="button primary" disabled={!canWrite} onClick={() => onSaveSOA(soaPayloadFromEditor(soaEditor))}><Save size={16} />保存 SOA</button>
            </div>
          </fieldset>
        ) : (
          <EmptyState text="当前 Zone 未返回可编辑的 SOA 记录" />
        )}
      </Panel>

      <Panel title="DNSSEC keys" subtitle="PowerDNS native key lifecycle; publish the returned DS at the parent zone">
        <div className="page-actions">
          <div className="muted">{cryptoKeys.length ? `${cryptoKeys.length} keys` : "No managed DNSSEC keys"}</div>
          <button className="button secondary" disabled={!canWrite} onClick={onCreateCryptoKey}><KeyRound size={16} />Create CSK</button>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>ID</th><th>Type</th><th>Active</th><th>Published</th><th>DS</th><th /></tr></thead>
            <tbody>
              {cryptoKeys.map((key) => (
                <tr key={key.id}>
                  <td>{key.id}</td>
                  <td>{key.keytype}</td>
                  <td>{key.active ? "yes" : "no"}</td>
                  <td>{key.published ? "yes" : "no"}</td>
                  <td><code>{key.ds?.[0] || "-"}</code></td>
                  <td>{canWrite && <button className="icon-button danger" onClick={() => onDeleteCryptoKey(key.id)}><Trash2 size={16} /></button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="record-toolbar">
        <label className="search-box"><Search size={16} /><input value={recordQuery} onChange={(event) => setRecordQuery(event.target.value)} placeholder="搜索名称、类型或内容" /></label>
        <select value={recordType} onChange={(event) => setRecordType(event.target.value)}>
          <option value="ALL">全部记录</option>
          {recordTypes.map((type) => <option key={type} value={type}>{type}</option>)}
        </select>
        <button className="button primary" disabled={!canWrite} onClick={() => setEditor(defaultRecordEditor)}><Plus size={16} />添加记录</button>
      </div>

      <div className="dns-record-layout">
        <Panel title="DNS 记录" subtitle={`${rrsets.length} 个记录集`}>
          {loading ? <LoadingState /> : (
            <RecordTable
              zoneName={zoneName}
              rrsets={rrsets}
              canWrite={canWrite}
              onEdit={(rrset) => setEditor({
                name: relativeRecordName(rrset.name, zoneName),
                type: rrset.type,
                ttl: String(rrset.ttl || 300),
                content: (rrset.records || []).map((record) => displayRecordContent(rrset.type, record.content)).join("\n"),
                originalName: rrset.name,
                originalType: rrset.type,
              })}
              onDelete={onDelete}
            />
          )}
        </Panel>

        <Panel title={editing ? "编辑记录集" : "添加 DNS 记录"} subtitle="每行内容会保存为同一名称和类型下的一条记录">
          <fieldset className="readonly-fieldset" disabled={!canWrite}>
            <div className="record-editor">
              <div className="record-editor-grid">
                <Field label="类型">
                  <select value={editor.type} onChange={(event) => setEditor({ ...editor, type: event.target.value })}>
                    {recordTypes.map((type) => <option key={type} value={type}>{type}</option>)}
                  </select>
                </Field>
                <Field label="名称">
                  <input value={editor.name} onChange={(event) => setEditor({ ...editor, name: event.target.value })} placeholder="@ 或 www" />
                </Field>
                <Field label="TTL">
                  <select value={editor.ttl} onChange={(event) => setEditor({ ...editor, ttl: event.target.value })}>
                    <option value="60">1 分钟</option>
                    <option value="300">5 分钟</option>
                    <option value="1800">30 分钟</option>
                    <option value="3600">1 小时</option>
                    <option value="86400">1 天</option>
                  </select>
                </Field>
              </div>
              <Field label="记录内容">
                <textarea
                  rows="5"
                  value={editor.content}
                  onChange={(event) => setEditor({ ...editor, content: event.target.value })}
                  placeholder={recordContentPlaceholder(editor.type, zoneName)}
                />
              </Field>
              <RecordHints type={editor.type} onTemplate={(content) => setEditor({ ...editor, type: "TXT", name: "_wallet", content })} />
              <div className="record-editor-actions">
                {editing && <button className="button secondary" onClick={() => setEditor(defaultRecordEditor)}>取消编辑</button>}
                <button className="button primary" disabled={!editor.name.trim() || !editor.content.trim()} onClick={onSave}><Save size={16} />保存记录</button>
              </div>
            </div>
          </fieldset>
        </Panel>
      </div>
    </div>
  );
}

function DelegationValue({ label, value }) {
  const copy = () => navigator.clipboard?.writeText(value);
  return (
    <div className="delegation-value">
      <span>{label}</span><code>{value}</code>
      <button className="icon-button" onClick={copy} title={`复制 ${label}`}><Copy size={14} /></button>
    </div>
  );
}

function RecordTable({ zoneName, rrsets, canWrite, onEdit, onDelete }) {
  return (
    <div className="table-wrap">
      <table className="record-table">
        <thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>状态</th><th /></tr></thead>
        <tbody>
          {rrsets.map((rrset) => {
            const protectedRecord = rrset.type === "SOA";
            const editableRecord = !protectedRecord && recordTypes.includes(rrset.type);
            return (
              <tr key={`${rrset.name}-${rrset.type}`}>
                <td><span className={`record-type type-${rrset.type.toLowerCase()}`}>{rrset.type}</span></td>
                <td><strong>{relativeRecordName(rrset.name, zoneName)}</strong><small className="record-fqdn">{rrset.name}</small></td>
                <td className="record-content">{(rrset.records || []).map((record) => <code key={record.content}>{record.content}</code>)}</td>
                <td className="mono">{rrset.ttl || "-"}</td>
                <td><HealthDot healthy={(rrset.records || []).some((record) => !record.disabled)} label={protectedRecord ? "系统" : "启用"} /></td>
                <td>
                  <div className="table-actions">
                    <button className="icon-button" disabled={!canWrite || !editableRecord} title={editableRecord ? "编辑记录" : "该记录类型仅支持查看"} onClick={() => onEdit(rrset)}><Edit3 size={15} /></button>
                    <button className="icon-button danger" disabled={!canWrite || protectedRecord} title={protectedRecord ? "SOA 由系统维护" : "删除记录"} onClick={() => onDelete(rrset)}><Trash2 size={15} /></button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {!rrsets.length && <EmptyState text="没有符合筛选条件的 DNS 记录" />}
    </div>
  );
}

function RecordHints({ type, onTemplate }) {
  return (
    <div className="record-hints">
      <span>{recordHint(type)}</span>
      {type === "TXT" && (
        <div>
          <button type="button" onClick={() => onTemplate("oa1:eth recipient_address=0x...; recipient_name=wallet;")}>OpenAlias ETH</button>
          <button type="button" onClick={() => onTemplate("oa1:btc recipient_address=bc1...; recipient_name=wallet;")}>OpenAlias BTC</button>
          <button type="button" onClick={() => onTemplate("chain=hns;address=hs1...")}>HNS Wallet</button>
        </div>
      )}
    </div>
  );
}

function PluginsPage({ dashboard, mutate, capabilities }) {
  const access = featureAccess(capabilities, "plugins");
  const canWrite = access.available && access.write;
  const plugins = dashboard?.plugins || [];
  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">PLUGINS</p><h2>去中心化域名插件</h2><p>控制 HNS、ENS、SNS、TON DNS、钱包记录等解析后端的实时启停。</p></div>
        <button className="button secondary" disabled={!canWrite} onClick={() => mutate(
          () => api("/api/v1/cache/flush", { method: "POST" }),
          "插件缓存已清理",
        )}><RotateCcw size={16} />清理缓存</button>
      </div>
      {!canWrite && <InlineWarning text="当前插件接口为只读，启停和缓存清理操作已禁用。" />}
      <Panel title="插件运行状态" subtitle={`${plugins.length} 个已注册插件`}>
        <PluginTable
          plugins={plugins}
          onToggle={canWrite ? (plugin) => mutate(
            () => api(`/api/v1/plugins/${encodeURIComponent(plugin.name)}/${plugin.enabled ? "disable" : "enable"}`, { method: "POST" }),
            `${plugin.name} 已${plugin.enabled ? "停用" : "启用"}`,
          ) : undefined}
        />
      </Panel>
    </div>
  );
}

function SecurityPage({ configuration, setConfiguration, saveConfiguration, dashboard, capabilities }) {
  const access = featureAccess(capabilities, "security");
  const canWrite = access.available && access.write && configuration?.writable;
  const security = configuration?.security;
  if (!security) return <EmptyState text="安全配置不可用" />;
  const update = (name, value) => setConfiguration({
    ...configuration,
    security: { ...security, [name]: value },
  });
  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">DNS SECURITY</p><h2>安全策略</h2><p>管理隧道检测、DGA、重绑定、速率限制、黑白名单和蜜罐联动。</p></div>
        <button className="button primary" disabled={!canWrite} onClick={() => saveConfiguration(configuration)}><Save size={16} />保存安全策略</button>
      </div>
      {!canWrite && <InlineWarning text={configuration.writable ? "当前凭据仅允许读取安全策略。" : "当前配置文件为只读，Docker 部署需要挂载共享可写配置卷。"} />}
      <fieldset className="readonly-fieldset" disabled={!canWrite}>
      <div className="security-layout">
        <Panel title="检测与阻断" subtitle="应用于 anyNS Runtime 的请求前后分析">
          <div className="settings-list">
            <ToggleRow label="启用 DNS 安全分析" detail="关闭后请求将直接进入插件路由" checked={security.enabled} onChange={(value) => update("enabled", value)} />
            <ToggleRow label="阻断 DNS Rebinding" detail="拒绝解析到私有、回环和链路本地地址" checked={security.block_rebinding} onChange={(value) => update("block_rebinding", value)} />
          </div>
          <div className="form-grid">
            <NumberField label="查询速率阈值" value={security.query_rate_threshold} onChange={(value) => update("query_rate_threshold", value)} />
            <NumberField label="查询窗口（秒）" value={security.query_rate_window_seconds} onChange={(value) => update("query_rate_window_seconds", value)} />
            <NumberField label="NXDOMAIN 阈值" value={security.nxdomain_threshold} onChange={(value) => update("nxdomain_threshold", value)} />
            <NumberField label="随机子域阈值" value={security.random_subdomain_threshold} onChange={(value) => update("random_subdomain_threshold", value)} />
            <NumberField label="DGA 熵阈值" step="0.1" value={security.dga_entropy_threshold} onChange={(value) => update("dga_entropy_threshold", value)} />
            <NumberField label="隧道 QNAME 长度" value={security.tunnel_max_qname_length} onChange={(value) => update("tunnel_max_qname_length", value)} />
          </div>
        </Panel>
        <Panel title="域名策略" subtitle="每行一个域名或后缀，后缀请以点开头">
          <ListEditor label="白名单" values={security.allowlist_domains || []} onChange={(values) => update("allowlist_domains", values)} />
          <ListEditor label="阻断列表" values={security.denylist_domains || []} onChange={(values) => update("denylist_domains", values)} />
          <ListEditor label="Sinkhole 列表" values={security.sinkhole_domains || []} onChange={(values) => update("sinkhole_domains", values)} />
        </Panel>
      </div>
      </fieldset>
      <Panel title="安全事件分布" subtitle="来自当前审计缓冲">
        <SummaryBars summary={dashboard?.audit_summary} />
      </Panel>
    </div>
  );
}

function AuditPage({ dashboard }) {
  const [query, setQuery] = useState("");
  const events = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return dashboard?.recent_events || [];
    return (dashboard?.recent_events || []).filter((event) =>
      [event.qname, event.client_ip, event.action, event.risk_level, event.source_plugin, event.matched_rule]
        .some((value) => String(value || "").toLowerCase().includes(normalized)),
    );
  }, [dashboard, query]);
  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">AUDIT</p><h2>DNS 与管理审计</h2><p>集中查看解析、安全动作、插件来源和管理变更。</p></div>
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索域名、规则或来源" /></label>
      </div>
      <Panel title="事件日志" subtitle={`显示 ${events.length} 条`}>
        <div className="table-wrap">
          <table>
            <thead><tr><th>时间</th><th>域名 / 路径</th><th>类型</th><th>来源</th><th>规则</th><th>动作</th><th>风险</th></tr></thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={event.trace_id || `${event.timestamp}-${index}`}>
                  <td className="mono muted">{formatTime(event.timestamp)}</td>
                  <td><strong>{event.qname || "-"}</strong><small>{event.client_ip || event.tenant || ""}</small></td>
                  <td className="mono">{event.qtype || "-"}</td>
                  <td>{event.source_plugin || "-"}</td>
                  <td>{event.matched_rule || "-"}</td>
                  <td><ActionTag action={event.action} /></td>
                  <td><RiskTag risk={event.risk_level} /></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!events.length && <EmptyState text="暂无匹配的审计事件" />}
        </div>
      </Panel>
    </div>
  );
}

function ConfigurationPage({ configuration, setConfiguration, saveConfiguration, capabilities }) {
  const access = featureAccess(capabilities, "config");
  const canWrite = access.available && access.write && configuration?.writable;
  if (!configuration) return <EmptyState text="配置不可用" />;
  const update = (section, name, value) => {
    if (!section) {
      setConfiguration({ ...configuration, [name]: value });
      return;
    }
    setConfiguration({
      ...configuration,
      [section]: { ...configuration[section], [name]: value },
    });
  };
  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">CONFIGURATION</p><h2>统一配置</h2><p>编辑 anyNS 与 PowerDNS 连接参数；密钥字段始终由服务端保留。</p></div>
        <button className="button primary" disabled={!canWrite} onClick={() => saveConfiguration(configuration)}><Save size={16} />保存并重载</button>
      </div>
      {!canWrite && <InlineWarning text={configuration.writable ? "当前凭据仅允许读取配置。" : `配置文件 ${configuration.config_file || "(未设置)"} 不可写。`} />}
      <fieldset className="readonly-fieldset page-stack" disabled={!canWrite}>
      <div className="two-column equal">
        <Panel title="PowerDNS 连接" subtitle="后端通过 X-API-Key 访问，密钥不在页面显示">
          <div className="form-grid single">
            <Field label="Authoritative API URL">
              <input value={configuration.powerdns.authoritative_url || ""} onChange={(event) => update("powerdns", "authoritative_url", event.target.value)} />
            </Field>
            <Field label="Recursor API URL">
              <input value={configuration.powerdns.recursor_url || ""} onChange={(event) => update("powerdns", "recursor_url", event.target.value)} />
            </Field>
            <Field label="Server ID">
              <input value={configuration.powerdns.server_id || ""} onChange={(event) => update("powerdns", "server_id", event.target.value)} />
            </Field>
            <NumberField label="请求超时（秒）" value={configuration.powerdns.request_timeout_seconds} onChange={(value) => update("powerdns", "request_timeout_seconds", value)} />
            <SecretState label="Authoritative API Key" configured={configuration.powerdns.authoritative_key_configured} />
            <SecretState label="Recursor API Key" configured={configuration.powerdns.recursor_key_configured} />
          </div>
        </Panel>
        <Panel title="控制面与日志" subtitle="实时控制和持久化审计配置">
          <div className="settings-list">
            <ToggleRow label="Admin 代理 Runtime 控制" detail="插件启停和缓存清理作用于真实数据面" checked={configuration.control_plane.admin_proxy_runtime} onChange={(value) => update("control_plane", "admin_proxy_runtime", value)} />
          </div>
          <div className="form-grid single">
            <Field label="Runtime Control URL">
              <input value={configuration.control_plane.runtime_control_url || ""} onChange={(event) => update("control_plane", "runtime_control_url", event.target.value)} />
            </Field>
            <NumberField label="全局请求超时（秒）" value={configuration.request_timeout_seconds} onChange={(value) => update(null, "request_timeout_seconds", value)} />
            <NumberField label="审计缓冲条数" value={configuration.dnslog.limit} onChange={(value) => update("dnslog", "limit", value)} />
            <Field label="审计日志路径">
              <input value={configuration.dnslog.path || ""} onChange={(event) => update("dnslog", "path", event.target.value)} />
            </Field>
          </div>
        </Panel>
      </div>
      <Panel title="插件后端配置" subtitle="API Key 保留在服务端，仅编辑非敏感连接参数">
        <div className="config-plugin-list">
          {configuration.plugins.map((plugin, index) => (
            <div className="config-plugin-row" key={plugin.name}>
              <div><strong>{plugin.name}</strong><span>{plugin.secret_configured ? "已配置密钥" : "无密钥"}</span></div>
              <Toggle checked={plugin.enabled} onChange={(enabled) => {
                const plugins = [...configuration.plugins];
                plugins[index] = { ...plugin, enabled };
                setConfiguration({ ...configuration, plugins });
              }} />
              <input value={plugin.backend_type || ""} placeholder="backend type" onChange={(event) => {
                const plugins = [...configuration.plugins];
                plugins[index] = { ...plugin, backend_type: event.target.value };
                setConfiguration({ ...configuration, plugins });
              }} />
              <input value={plugin.backend_url || ""} placeholder="Backend URL" onChange={(event) => {
                const plugins = [...configuration.plugins];
                plugins[index] = { ...plugin, backend_url: event.target.value };
                setConfiguration({ ...configuration, plugins });
              }} />
            </div>
          ))}
        </div>
      </Panel>
      </fieldset>
    </div>
  );
}

function PowerDNSService({ service, title }) {
  const statistics = service?.statistics || {};
  const entries = Object.entries(statistics).slice(0, 4);
  return (
    <div className="service-detail">
      <div className="service-detail-head">
        <div className="service-icon blue"><Database size={22} /></div>
        <div><h3>{title}</h3><span>{service?.server?.version ? `PowerDNS ${service.server.version}` : service?.url || "未配置"}</span></div>
        <StatusPill healthy={service?.healthy} configured={service?.configured} />
      </div>
      <div className="metric-row">
        <div><span>Zones</span><strong>{service?.zones?.length || 0}</strong></div>
        <div><span>Daemon</span><strong>{service?.server?.daemon_type || "-"}</strong></div>
        {entries.slice(0, 2).map(([key, value]) => <div key={key}><span>{key}</span><strong>{formatMetric(value)}</strong></div>)}
      </div>
      {service?.error && <InlineWarning text={service.error} />}
    </div>
  );
}

function Panel({ title, subtitle, action, children, className = "" }) {
  return (
    <article className={`panel ${className}`}>
      <header><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div>{action}</header>
      <div className="panel-body">{children}</div>
    </article>
  );
}

function PluginTable({ plugins = [], onToggle, compact = false }) {
  return (
    <div className="table-wrap">
      <table className={compact ? "compact-table" : ""}>
        <thead><tr><th>插件</th><th>域名后缀</th><th>状态</th><th>健康</th>{onToggle && <th>操作</th>}</tr></thead>
        <tbody>
          {plugins.map((plugin) => (
            <tr key={plugin.name}>
              <td><strong>{plugin.name}</strong>{plugin.last_error && <small>{plugin.last_error}</small>}</td>
              <td className="mono muted">{plugin.suffixes?.join(", ") || "精确域名"}</td>
              <td><span className={`state-label ${plugin.enabled ? "enabled" : "disabled"}`}>{plugin.enabled ? "已启用" : "已停用"}</span></td>
              <td><HealthDot healthy={plugin.healthy} label={plugin.healthy ? "健康" : "异常"} /></td>
              {onToggle && <td><Toggle checked={plugin.enabled} onChange={() => onToggle(plugin)} /></td>}
            </tr>
          ))}
        </tbody>
      </table>
      {!plugins.length && <EmptyState text="没有已注册插件" />}
    </div>
  );
}

function ZoneTable({ zones = [], onDelete, onSelect, compact = false }) {
  return (
    <div className="table-wrap">
      <table className={compact ? "compact-table" : ""}>
        <thead><tr><th>域名</th><th>类型</th><th>Serial</th><th>DNSSEC</th><th>状态</th>{(onDelete || onSelect) && <th />}</tr></thead>
        <tbody>
          {zones.map((zone) => (
            <tr key={zone.id || zone.name}>
              <td>
                <strong>{zone.unicode_name || zone.name}</strong>
                {zone.unicode_name && zone.unicode_name !== zone.name && <small className="zone-punycode">{zone.name}</small>}
                {isHNSZoneName(zone.name) && <small className="zone-hns-alias">{trimTrailingDot(zone.unicode_name || zone.name)}.hns</small>}
              </td>
              <td>{zone.kind || "-"}</td>
              <td className="mono">{zone.serial || "-"}</td>
              <td>{zone.dnssec ? <HealthDot healthy label="已启用" /> : <span className="muted">未启用</span>}</td>
              <td><HealthDot healthy label="正常" /></td>
              {(onDelete || onSelect) && <td><div className="table-actions">
                {onSelect && <button className="button secondary zone-manage" onClick={() => onSelect(zone)}>管理记录<ChevronRight size={14} /></button>}
                {onDelete && <button className="icon-button danger" title="删除 Zone" onClick={() => onDelete(zone)}><Trash2 size={16} /></button>}
              </div></td>}
            </tr>
          ))}
        </tbody>
      </table>
      {!zones.length && <EmptyState text="PowerDNS 尚无 Zone，或服务未连接" />}
    </div>
  );
}

function isHNSZoneName(value = "") {
  const normalized = trimTrailingDot(value);
  return Boolean(normalized) && !normalized.includes(".");
}

function absoluteRecordName(value, zoneName) {
  const zone = ensureTrailingDot(zoneName);
  const name = value.trim();
  if (!name || name === "@") return zone;
  const absolute = ensureTrailingDot(name);
  if (absolute === zone || absolute.endsWith(`.${zone}`)) return absolute;
  return `${trimTrailingDot(name)}.${zone}`;
}

function relativeRecordName(value, zoneName) {
  const name = ensureTrailingDot(value);
  const zone = ensureTrailingDot(zoneName);
  if (name === zone) return "@";
  return trimTrailingDot(name.slice(0, -(zone.length + 1)));
}

function formatRecordContent(type, value) {
  const content = value.trim();
  if (!content) return "";
  if (type !== "TXT" || (content.startsWith('"') && content.endsWith('"'))) return content;
  return `"${content.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function displayRecordContent(type, value) {
  if (type === "TXT" && value.startsWith('"') && value.endsWith('"')) return value.slice(1, -1);
  return value;
}

function recordContentPlaceholder(type, zoneName) {
  const examples = {
    A: authoritativeIPv4Example,
    AAAA: "2001:db8::53",
    CNAME: `target.${zoneName}`,
    TXT: "verification=... 或钱包记录",
    MX: `10 mail.${zoneName}`,
    NS: `ns1.${zoneName}`,
    SRV: `10 5 443 service.${zoneName}`,
    CAA: '0 issue "letsencrypt.org"',
    DS: "12345 13 2 <sha256-digest>",
    DNSKEY: "257 3 13 <base64-public-key>",
    PTR: `host.${zoneName}`,
    SVCB: `1 service.${zoneName} alpn=h2,h3`,
    HTTPS: `1 . alpn=h2,h3 ipv4hint=${authoritativeIPv4Example}`,
    TLSA: "3 1 1 <certificate-sha256>",
  };
  return examples[type] || "记录内容";
}

function recordHint(type) {
  const hints = {
    DS: "Format: key-tag algorithm digest-type digest. Prefer digest type 2 or 4.",
    DNSKEY: "Format: flags protocol algorithm base64-key. Use managed PowerDNS keys for signed zones.",
    A: "填写 IPv4 地址。@ 表示 Zone 根域名。",
    AAAA: "填写 IPv6 地址。",
    CNAME: "目标必须使用完整域名，建议以点结尾。",
    TXT: "输入时无需外层引号；支持每行一条值和钱包模板。",
    MX: "格式：优先级 邮件服务器，例如 10 mail.example.",
    NS: "格式：完整 Nameserver 域名。HNS 链上还需发布 NS/GLUE。",
    SRV: "格式：优先级 权重 端口 目标。",
    CAA: '格式：标志 标签 值，例如 0 issue "letsencrypt.org"',
    PTR: "填写反向解析目标的完整域名。",
    SVCB: "格式：优先级 目标 参数。",
    HTTPS: "用于 HTTPS/SVCB 服务绑定和 HTTP/3 等现代解析提示。",
    TLSA: "格式：证书用途 选择器 匹配类型 证书数据。",
  };
  return hints[type] || "每行保存为同一 RRSet 下的一条记录。";
}

function TrafficChart({ events }) {
  const points = useMemo(() => buildTrafficPoints(events), [events]);
  const width = 680;
  const height = 218;
  const max = Math.max(1, ...points.flatMap((point) => [point.safe, point.blocked]));
  const line = (key) => points.map((point, index) => {
    const x = 22 + (index * (width - 44)) / Math.max(points.length - 1, 1);
    const y = height - 24 - (point[key] * (height - 58)) / max;
    return `${x},${y}`;
  }).join(" ");
  return (
    <div className="chart">
      <div className="chart-legend"><span><i className="safe" />安全请求</span><span><i className="blocked" />阻断/限速</span></div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="最近请求活动">
        {[0, 1, 2, 3].map((lineIndex) => <line key={lineIndex} x1="22" x2={width - 22} y1={34 + lineIndex * 45} y2={34 + lineIndex * 45} className="grid-line" />)}
        <polyline points={line("safe")} className="chart-line safe-line" />
        <polyline points={line("blocked")} className="chart-line blocked-line" />
      </svg>
      {!events.length && <span className="chart-empty">等待 DNS 请求事件</span>}
    </div>
  );
}

function EventList({ events }) {
  if (!events.length) return <EmptyState text="暂无安全事件" />;
  return (
    <div className="event-list">
      {events.map((event, index) => (
        <div className="event-row" key={event.trace_id || index}>
          <div className={`event-icon ${["block", "rate_limit", "forward_to_honeypot"].includes(event.action) ? "danger" : "safe"}`}>
            {["block", "rate_limit", "forward_to_honeypot"].includes(event.action) ? <CircleAlert size={15} /> : <Check size={15} />}
          </div>
          <div><strong>{event.qname || event.matched_rule || "DNS 事件"}</strong><span>{event.matched_rule || event.source_plugin || "-"}</span></div>
          <ActionTag action={event.action} />
          <time>{formatTime(event.timestamp, true)}</time>
        </div>
      ))}
    </div>
  );
}

function SummaryBars({ summary }) {
  const items = Object.entries(summary?.by_action || {});
  const max = Math.max(1, ...items.map(([, value]) => value));
  if (!items.length) return <EmptyState text="暂无安全事件统计" />;
  return <div className="summary-bars">{items.map(([name, value]) => (
    <div key={name}><span>{labelAction(name)}</span><div><i style={{ width: `${(value / max) * 100}%` }} /></div><strong>{value}</strong></div>
  ))}</div>;
}

function StatusPill({ healthy, configured }) {
  if (!configured) return <span className="status-pill neutral">未配置</span>;
  return <span className={`status-pill ${healthy ? "ok" : "error"}`}><i />{healthy ? "运行中" : "异常"}</span>;
}

function HealthDot({ healthy, label }) {
  return <span className={`health-dot ${healthy ? "ok" : "error"}`}><i />{label}</span>;
}

function ActionTag({ action }) {
  const dangerous = ["block", "rate_limit", "forward_to_honeypot"].includes(action);
  return <span className={`tag ${dangerous ? "red" : "green"}`}>{labelAction(action)}</span>;
}

function RiskTag({ risk }) {
  const tone = risk === "critical" || risk === "high" ? "red" : risk === "medium" ? "orange" : "gray";
  return <span className={`tag ${tone}`}>{risk || "none"}</span>;
}

function Toggle({ checked, onChange }) {
  return <button type="button" role="switch" aria-checked={checked} className={`toggle ${checked ? "on" : ""}`} onClick={() => onChange(!checked)}><span /></button>;
}

function ToggleRow({ label, detail, checked, onChange }) {
  return <div className="toggle-row"><div><strong>{label}</strong><span>{detail}</span></div><Toggle checked={checked} onChange={onChange} /></div>;
}

function ListEditor({ label, values, onChange }) {
  return <Field label={label}><textarea rows="4" value={values.join("\n")} onChange={(event) => onChange(event.target.value.split("\n").map((value) => value.trim()).filter(Boolean))} /></Field>;
}

function Field({ label, children }) {
  return <label className="field"><span>{label}</span>{children}</label>;
}

function NumberField({ label, value, onChange, step = "1" }) {
  return <Field label={label}><input type="number" step={step} value={value ?? ""} onChange={(event) => onChange(Number(event.target.value))} /></Field>;
}

function SecretState({ label, configured }) {
  return <div className="secret-state"><KeyRound size={16} /><span>{label}</span><b>{configured ? "已在服务端配置" : "未配置"}</b></div>;
}

function InlineWarning({ text }) {
  return <div className="inline-warning"><CircleAlert size={17} /><span>{text}</span></div>;
}

function EmptyState({ text }) {
  return <div className="empty-state"><Database size={22} /><span>{text}</span></div>;
}

function LoadingState() {
  return <div className="loading-state"><LoaderCircle size={28} className="spin" /><strong>正在读取控制面状态</strong><span>连接 anyNS Admin API 与 PowerDNS</span></div>;
}

function Toast({ type, message, onClose }) {
  return <div className={`toast ${type}`}><span>{type === "success" ? <Check size={17} /> : <CircleAlert size={17} />}{message}</span><button onClick={onClose}><X size={16} /></button></div>;
}

function ConnectionBadge({ dashboard }) {
  const services = dashboard?.services;
  const healthy = services && services.admin?.healthy && services.runtime?.healthy;
  return <span className={`connection-badge ${healthy ? "ok" : "warn"}`}><i />{healthy ? "服务器连接：健康" : "服务状态需检查"}</span>;
}

function AuthDialog({ onClose, onSaved }) {
  const [value, setValue] = useState(getToken());
  return (
    <div className="dialog-backdrop">
      <div className="dialog">
        <div className="dialog-icon"><KeyRound size={22} /></div>
        <h2>管理 API 令牌</h2>
        <p>启用管理鉴权时使用 Bearer Token。令牌仅保存在当前浏览器会话。</p>
        <input type="password" autoFocus value={value} onChange={(event) => setValue(event.target.value)} placeholder="输入管理令牌" />
        <div className="dialog-actions">
          <button className="button secondary" onClick={() => { setToken(""); onClose(); onSaved(); }}><LogOut size={16} />清除令牌</button>
          <button className="button primary" onClick={() => { setToken(value.trim()); onClose(); onSaved(); }}><Check size={16} />保存并连接</button>
        </div>
      </div>
    </div>
  );
}

function buildTrafficPoints(events = []) {
  const buckets = Array.from({ length: 18 }, () => ({ safe: 0, blocked: 0 }));
  if (!events.length) return buckets;
  const timestamps = events.map((event) => new Date(event.timestamp).getTime()).filter(Number.isFinite);
  const latest = Math.max(...timestamps);
  const earliest = latest - 60 * 60 * 1000;
  events.forEach((event) => {
    const time = new Date(event.timestamp).getTime();
    const index = Math.max(0, Math.min(buckets.length - 1, Math.floor(((time - earliest) / (latest - earliest || 1)) * buckets.length)));
    if (["block", "rate_limit", "forward_to_honeypot"].includes(event.action)) buckets[index].blocked += 1;
    else buckets[index].safe += 1;
  });
  return buckets;
}

function statValue(statistics = {}, names) {
  for (const name of names) {
    if (statistics?.[name] != null) return formatMetric(statistics[name]);
  }
  return "";
}

function formatMetric(value) {
  if (typeof value === "object") return Array.isArray(value) ? value.length : "详情";
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return new Intl.NumberFormat("zh-CN", { notation: numeric > 9999 ? "compact" : "standard" }).format(numeric);
  return String(value ?? "-");
}

function formatTime(value, short = false) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", short
    ? { hour: "2-digit", minute: "2-digit", hour12: false }
    : { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }
  ).format(date);
}

function labelAction(action) {
  return {
    allow: "放行",
    log_only: "记录",
    block: "阻断",
    sinkhole: "Sinkhole",
    rate_limit: "限速",
    forward_to_honeypot: "蜜罐",
    management_mutation: "管理变更",
  }[action] || action || "未知";
}

export default App;

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Blocks,
  BookOpenCheck,
  Check,
  ChevronRight,
  CircleAlert,
  Database,
  FileClock,
  Gauge,
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

const navigation = [
  { id: "overview", label: "总览", icon: Gauge },
  { id: "powerdns", label: "PowerDNS", icon: Layers3 },
  { id: "plugins", label: "插件", icon: Blocks },
  { id: "security", label: "DNS 安全", icon: ShieldCheck },
  { id: "audit", label: "审计日志", icon: FileClock },
  { id: "config", label: "配置", icon: Settings },
];

function App() {
  const [page, setPage] = useState("overview");
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
      const data = await api("/api/v1/dashboard?event_limit=50");
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

  const activeItem = navigation.find((item) => item.id === page);
  const contentProps = {
    dashboard,
    configuration,
    setConfiguration,
    mutate,
    load,
    saveConfiguration,
  };

  return (
    <div className="app-shell">
      <Sidebar
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

function Sidebar({ page, setPage, open, onClose }) {
  return (
    <>
      {open && <button className="sidebar-scrim" onClick={onClose} aria-label="关闭导航" />}
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Network size={23} /></div>
          <div><strong>anyNS</strong><span>Control Plane</span></div>
        </div>
        <nav>
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={page === id ? "active" : ""}
              onClick={() => { setPage(id); onClose(); }}
            >
              <Icon size={19} />
              <span>{label}</span>
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

function Overview({ dashboard, mutate, setPage }) {
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
          <button className="button secondary" onClick={() => mutate(
            () => api("/api/v1/cache/flush", { method: "POST" }),
            "anyNS 插件缓存已清理",
          )}><RotateCcw size={16} />清理插件缓存</button>
          <button className="button primary" onClick={() => mutate(
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
          action={<button className="text-button" onClick={() => setPage("audit")}>查看全部</button>}
        >
          <TrafficChart events={events} />
        </Panel>
        <Panel title="近期安全事件" subtitle="按时间倒序" action={<button className="text-button" onClick={() => setPage("audit")}>查看全部</button>}>
          <EventList events={events.slice(0, 7)} />
        </Panel>
        <Panel title="PowerDNS Zones" subtitle={`${zones.length} 个权威区域`} action={<button className="text-button" onClick={() => setPage("powerdns")}>管理区域</button>}>
          <ZoneTable zones={zones.slice(0, 6)} compact />
        </Panel>
        <Panel title="anyNS 插件" subtitle={`${plugins.filter((item) => item.enabled).length}/${plugins.length} 已启用`} action={<button className="text-button" onClick={() => setPage("plugins")}>管理插件</button>}>
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

function PowerDNSPage({ dashboard, mutate }) {
  const snapshot = dashboard?.services?.powerdns || {};
  const zones = snapshot.authoritative?.zones || [];
  const [zoneName, setZoneName] = useState("");
  const [nameserver, setNameserver] = useState("");
  const [flushDomain, setFlushDomain] = useState("");

  const createZone = () => mutate(async () => {
    await api("/api/v1/powerdns/authoritative/zones", {
      method: "POST",
      body: JSON.stringify({
        name: zoneName,
        kind: "Native",
        nameservers: nameserver ? [nameserver] : [],
      }),
    });
    setZoneName("");
    setNameserver("");
  }, `Zone ${zoneName} 已创建`);

  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">POWERDNS</p><h2>权威与递归服务</h2><p>API 密钥仅由 anyNS 后端持有，浏览器不直接连接 PowerDNS。</p></div>
      </div>
      <div className="split-status">
        <PowerDNSService service={snapshot.authoritative} title="Authoritative" />
        <PowerDNSService service={snapshot.recursor} title="Recursor" />
      </div>
      <div className="two-column">
        <Panel title="权威区域" subtitle={`${zones.length} 个 Zone`}>
          <ZoneTable
            zones={zones}
            onDelete={(zone) => mutate(
              () => api(`/api/v1/powerdns/authoritative/zones/${encodeURIComponent(zone.id)}`, { method: "DELETE" }),
              `Zone ${zone.name} 已删除`,
            )}
          />
        </Panel>
        <div className="form-stack">
          <Panel title="创建 Authoritative Zone" subtitle="通过 PowerDNS Authoritative API">
            <div className="form-grid single">
              <Field label="Zone 名称">
                <input value={zoneName} onChange={(event) => setZoneName(event.target.value)} placeholder="example.org" />
              </Field>
              <Field label="初始 Nameserver">
                <input value={nameserver} onChange={(event) => setNameserver(event.target.value)} placeholder="ns1.example.org." />
              </Field>
              <button className="button primary" disabled={!zoneName} onClick={createZone}><Plus size={16} />创建 Zone</button>
            </div>
          </Panel>
          <Panel title="清理 Recursor 缓存" subtitle="支持单域名或子树缓存">
            <div className="form-grid single">
              <Field label="域名（留空表示全部）">
                <input value={flushDomain} onChange={(event) => setFlushDomain(event.target.value)} placeholder="example.org" />
              </Field>
              <button className="button secondary" onClick={() => mutate(
                () => api("/api/v1/powerdns/recursor/cache/flush", {
                  method: "POST",
                  body: JSON.stringify({ domain: flushDomain, subtree: true }),
                }),
                "Recursor 缓存已清理",
              )}><RotateCcw size={16} />清理缓存子树</button>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function PluginsPage({ dashboard, mutate }) {
  const plugins = dashboard?.plugins || [];
  return (
    <div className="page-stack">
      <div className="page-actions">
        <div><p className="section-kicker">PLUGINS</p><h2>去中心化域名插件</h2><p>控制 HNS、ENS、SNS、TON DNS、钱包记录等解析后端的实时启停。</p></div>
        <button className="button secondary" onClick={() => mutate(
          () => api("/api/v1/cache/flush", { method: "POST" }),
          "插件缓存已清理",
        )}><RotateCcw size={16} />清理缓存</button>
      </div>
      <Panel title="插件运行状态" subtitle={`${plugins.length} 个已注册插件`}>
        <PluginTable
          plugins={plugins}
          onToggle={(plugin) => mutate(
            () => api(`/api/v1/plugins/${encodeURIComponent(plugin.name)}/${plugin.enabled ? "disable" : "enable"}`, { method: "POST" }),
            `${plugin.name} 已${plugin.enabled ? "停用" : "启用"}`,
          )}
        />
      </Panel>
    </div>
  );
}

function SecurityPage({ configuration, setConfiguration, saveConfiguration, dashboard }) {
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
        <button className="button primary" disabled={!configuration?.writable} onClick={() => saveConfiguration(configuration)}><Save size={16} />保存安全策略</button>
      </div>
      {!configuration.writable && <InlineWarning text="当前配置文件为只读，Docker 部署需要挂载共享可写配置卷。" />}
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

function ConfigurationPage({ configuration, setConfiguration, saveConfiguration }) {
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
        <button className="button primary" disabled={!configuration.writable} onClick={() => saveConfiguration(configuration)}><Save size={16} />保存并重载</button>
      </div>
      {!configuration.writable && <InlineWarning text={`配置文件 ${configuration.config_file || "(未设置)"} 不可写。`} />}
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

function ZoneTable({ zones = [], onDelete, compact = false }) {
  return (
    <div className="table-wrap">
      <table className={compact ? "compact-table" : ""}>
        <thead><tr><th>域名</th><th>类型</th><th>Serial</th><th>DNSSEC</th><th>状态</th>{onDelete && <th />}</tr></thead>
        <tbody>
          {zones.map((zone) => (
            <tr key={zone.id || zone.name}>
              <td><strong>{zone.name}</strong></td>
              <td>{zone.kind || "-"}</td>
              <td className="mono">{zone.serial || "-"}</td>
              <td>{zone.dnssec ? <HealthDot healthy label="已启用" /> : <span className="muted">未启用</span>}</td>
              <td><HealthDot healthy label="正常" /></td>
              {onDelete && <td><button className="icon-button danger" title="删除 Zone" onClick={() => onDelete(zone)}><Trash2 size={16} /></button></td>}
            </tr>
          ))}
        </tbody>
      </table>
      {!zones.length && <EmptyState text="PowerDNS 尚无 Zone，或服务未连接" />}
    </div>
  );
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

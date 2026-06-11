runtime_endpoint = os.getenv("ANYNS_RUNTIME_ENDPOINT") or "http://anyns-plugin-runtime:8081/api/v1/resolve"
runtime_client_view = os.getenv("ANYNS_CLIENT_VIEW") or "default"
runtime_tenant = os.getenv("ANYNS_TENANT") or "default"
runtime_policy_tags = os.getenv("ANYNS_POLICY_TAGS") or ""
runtime_timeout_seconds = tonumber(os.getenv("ANYNS_RUNTIME_TIMEOUT_SECONDS") or "3") or 3
rcode_noerror = pdns.NOERROR or 0
rcode_nxdomain = pdns.NXDOMAIN or 3
rcode_servfail = pdns.SERVFAIL or 2

local ok_http, http = pcall(require, "socket.http")
local ok_ltn12, ltn12 = pcall(require, "ltn12")
local ok_json, json = pcall(require, "cjson.safe")

local rr_types = {
  A = pdns.A,
  AAAA = pdns.AAAA,
  CNAME = pdns.CNAME,
  TXT = pdns.TXT,
  MX = pdns.MX,
  NS = pdns.NS,
  SRV = pdns.SRV,
  DS = pdns.DS,
  CAA = pdns.CAA,
  TLSA = pdns.TLSA,
  SVCB = pdns.SVCB,
  HTTPS = pdns.HTTPS
}

local qtype_names = {
  [1] = "A",
  [2] = "NS",
  [5] = "CNAME",
  [6] = "SOA",
  [12] = "PTR",
  [15] = "MX",
  [16] = "TXT",
  [28] = "AAAA",
  [33] = "SRV",
  [43] = "DS",
  [46] = "RRSIG",
  [47] = "NSEC",
  [48] = "DNSKEY",
  [52] = "TLSA",
  [64] = "SVCB",
  [65] = "HTTPS",
  [255] = "ANY",
  [256] = "URI",
  [257] = "CAA",
  [262] = "TYPE262"
}

local function qtype_name(qtype)
  if type(qtype) == "number" then
    return qtype_names[qtype] or ("TYPE" .. tostring(qtype))
  end
  local ok, name = pcall(function()
    return qtype:toString()
  end)
  if ok and name ~= nil and name ~= "" then
    return string.upper(tostring(name))
  end
  return string.upper(tostring(qtype))
end

local function json_escape(value)
  value = tostring(value or "")
  value = value:gsub("\\", "\\\\")
  value = value:gsub("\"", "\\\"")
  return value
end

local function runtime_available()
  return ok_http and ok_ltn12 and ok_json
end

local function status_allows_runtime_result(status)
  return status == 200 or status == 403 or status == 429
end

local function policy_tags_json()
  local tags = {}
  for tag in string.gmatch(runtime_policy_tags, "([^,]+)") do
    tag = tag:gsub("^%s+", ""):gsub("%s+$", "")
    if tag ~= "" then
      table.insert(tags, '"' .. json_escape(tag) .. '"')
    end
  end
  return "[" .. table.concat(tags, ",") .. "]"
end

local function runtime_resolve(dq)
  if not runtime_available() then
    pdnslog("anyNS runtime Lua dependencies are unavailable; falling back to ICANN recursion", pdns.loglevels.Warning)
    return nil
  end

  http.TIMEOUT = runtime_timeout_seconds
  local body = string.format(
    '{"qname":"%s","qtype":"%s","context":{"trace_id":"pdns-lua","client_ip":"%s","client_view":"%s","tenant":"%s","transport":"udp","protocol":"dns","policy_tags":%s}}',
    json_escape(dq.qname:toString()),
    json_escape(qtype_name(dq.qtype)),
    json_escape(tostring(dq.remoteaddr)),
    json_escape(runtime_client_view),
    json_escape(runtime_tenant),
    policy_tags_json()
  )
  local chunks = {}
  local _, status = http.request({
    url = runtime_endpoint,
    method = "POST",
    headers = {
      ["Content-Type"] = "application/json",
      ["Content-Length"] = tostring(#body)
    },
    source = ltn12.source.string(body),
    sink = ltn12.sink.table(chunks)
  })
  if not status_allows_runtime_result(status) then
    return nil
  end
  local decoded = json.decode(table.concat(chunks))
  if not decoded or not decoded.result then
    return nil
  end
  return decoded.result
end

local function answer_value(rr_name, value)
  value = tostring(value or "")
  if rr_name == "TXT" then
    value = value:gsub("\\", "\\\\"):gsub('"', '\\"')
    return '"' .. value .. '"'
  end
  return value
end

local function add_runtime_answers(dq, result)
  local added = 0
  for _, rr in ipairs(result.rrset or {}) do
    local rr_name = string.upper(tostring(rr.type or ""))
    local rr_type = rr_types[rr_name]
    if rr_type ~= nil then
      dq:addAnswer(rr_type, answer_value(rr_name, rr.value), rr.ttl or result.ttl or 60)
      added = added + 1
    elseif rr_name == "WALLET" or rr_name == "TYPE262" then
      pdnslog("anyNS runtime returned WALLET/TYPE262; configure authoritative TYPE262 handling for this RR", pdns.loglevels.Info)
    else
      pdnslog("anyNS runtime returned unsupported RR type: " .. rr_name, pdns.loglevels.Warning)
    end
  end
  return added
end

local function apply_runtime_result(dq, result)
  local rcode = string.upper(tostring(result.rcode or ""))
  if rcode == "NOERROR" then
    dq.rcode = rcode_noerror
    local added = add_runtime_answers(dq, result)
    if added == 0 then
      pdnslog("anyNS runtime returned NOERROR without answers; returning NODATA without ICANN fallback", pdns.loglevels.Info)
    end
    return true
  end
  if rcode == "NXDOMAIN" then
    dq.rcode = rcode_nxdomain
    pdnslog("anyNS runtime returned NXDOMAIN; suppressing ICANN fallback for routed name", pdns.loglevels.Info)
    return true
  end
  if rcode == "SERVFAIL" then
    dq.rcode = rcode_servfail
    pdnslog("anyNS runtime returned SERVFAIL; suppressing ICANN fallback for routed name", pdns.loglevels.Warning)
    return true
  end
  pdnslog("anyNS runtime returned unsupported rcode: " .. rcode, pdns.loglevels.Warning)
  return false
end

function preresolve(dq)
  pdnslog("anyNS recursor hook saw query: " .. dq.qname:toString() .. " " .. qtype_name(dq.qtype), pdns.loglevels.Info)
  local result = runtime_resolve(dq)
  if not result then
    return false
  end
  return apply_runtime_result(dq, result)
end

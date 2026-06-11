package pdnshook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecursorLuaHookRuntimeContract(t *testing.T) {
	hook := readHook(t)
	required := []string{
		`runtime_endpoint = os.getenv("ANYNS_RUNTIME_ENDPOINT")`,
		`runtime_client_view = os.getenv("ANYNS_CLIENT_VIEW")`,
		`runtime_tenant = os.getenv("ANYNS_TENANT")`,
		`runtime_policy_tags = os.getenv("ANYNS_POLICY_TAGS")`,
		`runtime_timeout_seconds = tonumber(os.getenv("ANYNS_RUNTIME_TIMEOUT_SECONDS")`,
		`pcall(require, "socket.http")`,
		`pcall(require, "ltn12")`,
		`pcall(require, "cjson.safe")`,
		`local function status_allows_runtime_result(status)`,
		`return status == 200 or status == 403 or status == 429`,
		`DS = pdns.DS`,
		`TLSA = pdns.TLSA`,
		`SVCB = pdns.SVCB`,
		`HTTPS = pdns.HTTPS`,
		`local function policy_tags_json()`,
		`local function qtype_name(qtype)`,
		`if type(qtype) == "number" then`,
		`return qtype_names[qtype] or ("TYPE" .. tostring(qtype))`,
		`return qtype:toString()`,
		`json_escape(qtype_name(dq.qtype))`,
		`"qname":"%s","qtype":"%s","context"`,
		`"trace_id":"pdns-lua"`,
		`"client_ip":"%s"`,
		`"client_view":"%s"`,
		`"tenant":"%s"`,
		`"transport":"udp","protocol":"dns"`,
		`"policy_tags":%s`,
		`local rr_name = string.upper(tostring(rr.type or ""))`,
		`local rr_type = rr_types[rr_name]`,
		`dq:addAnswer(rr_type, rr.value, rr.ttl or result.ttl or 60)`,
		`local function apply_runtime_result(dq, result)`,
		`local rcode = string.upper(tostring(result.rcode or ""))`,
		`rcode_noerror = pdns.NOERROR or 0`,
		`rcode_nxdomain = pdns.NXDOMAIN or 3`,
		`rcode_servfail = pdns.SERVFAIL or 2`,
		`dq.rcode = rcode_noerror`,
		`dq.rcode = rcode_nxdomain`,
		`dq.rcode = rcode_servfail`,
		`return apply_runtime_result(dq, result)`,
	}
	for _, needle := range required {
		if !strings.Contains(hook, needle) {
			t.Fatalf("recursor.lua missing runtime contract fragment %q", needle)
		}
	}
}

func TestRecursorLuaHookSupportsNumericQTypes(t *testing.T) {
	hook := readHook(t)
	for _, needle := range []string{
		`[1] = "A"`,
		`[16] = "TXT"`,
		`[64] = "SVCB"`,
		`[65] = "HTTPS"`,
		`[262] = "TYPE262"`,
	} {
		if !strings.Contains(hook, needle) {
			t.Fatalf("recursor.lua missing numeric qtype mapping %q", needle)
		}
	}
	if strings.Contains(hook, `dq.qtype:toString()`) {
		t.Fatalf("recursor.lua must normalize numeric qtypes before rendering them")
	}
}

func TestRecursorLuaHookFallsBackSafely(t *testing.T) {
	hook := readHook(t)
	required := []string{
		`falling back to ICANN recursion`,
		`if not status_allows_runtime_result(status) then`,
		`return nil`,
		`if not decoded or not decoded.result then`,
		`return false`,
	}
	for _, needle := range required {
		if !strings.Contains(hook, needle) {
			t.Fatalf("recursor.lua missing fallback fragment %q", needle)
		}
	}
	if strings.Contains(hook, "X-anyNS-Signature") {
		t.Fatalf("recursor.lua should not sign runtime requests; HMAC is reserved for honeypot delivery")
	}
}

func TestRecursorLuaHookHonorsRuntimeSecurityStatuses(t *testing.T) {
	hook := readHook(t)
	if strings.Contains(hook, `if status ~= 200 then`) {
		t.Fatalf("recursor.lua must not discard runtime security result bodies solely because status is non-200")
	}
	for _, needle := range []string{
		`status == 403`,
		`status == 429`,
		`json.decode(table.concat(chunks))`,
		`return decoded.result`,
	} {
		if !strings.Contains(hook, needle) {
			t.Fatalf("recursor.lua missing security status handling fragment %q", needle)
		}
	}
}

func TestRecursorLuaHookSuppressesICANNFallbackForRuntimeRcodes(t *testing.T) {
	hook := readHook(t)
	required := []string{
		`rcode == "NOERROR"`,
		`returning NODATA without ICANN fallback`,
		`rcode == "NXDOMAIN"`,
		`suppressing ICANN fallback for routed name`,
		`rcode == "SERVFAIL"`,
		`return true`,
	}
	for _, needle := range required {
		if !strings.Contains(hook, needle) {
			t.Fatalf("recursor.lua missing runtime rcode handling fragment %q", needle)
		}
	}
}

func TestRecursorLuaHookDocumentsUnsupportedWalletAnswers(t *testing.T) {
	hook := readHook(t)
	if !strings.Contains(hook, `rr_name == "WALLET" or rr_name == "TYPE262"`) {
		t.Fatalf("recursor.lua should explicitly handle WALLET/TYPE262 runtime answers")
	}
	if !strings.Contains(hook, `configure authoritative TYPE262 handling`) {
		t.Fatalf("recursor.lua should document TYPE262 handling in the log path")
	}
}

func readHook(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "configs", "pdns-recursor", "recursor.lua")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

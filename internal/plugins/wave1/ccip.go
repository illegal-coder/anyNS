package wave1

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	offchainLookupSelector = "556f1830"
	maxCCIPResponseBytes   = 1 << 20
	maxCCIPDepth           = 2
)

type offchainLookup struct {
	Sender           string
	URLs             []string
	CallData         []byte
	CallbackFunction []byte
	ExtraData        []byte
}

func ccipRead(
	ctx context.Context,
	client *http.Client,
	backendURL, apiKey string,
	timeout time.Duration,
	to string,
	errorData json.RawMessage,
	depth int,
) (string, error) {
	if depth >= maxCCIPDepth {
		return "", errors.New("CCIP-Read recursion limit exceeded")
	}
	encoded := extractRPCErrorData(errorData)
	lookup, err := decodeOffchainLookup(encoded)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(lookup.Sender, to) {
		return "", errors.New("CCIP-Read sender does not match resolver")
	}
	response, err := fetchCCIPResponse(ctx, client, lookup)
	if err != nil {
		return "", err
	}
	callbackData := encodeCCIPCallback(lookup.CallbackFunction, response, lookup.ExtraData)
	return ethCallDepth(ctx, client, backendURL, apiKey, timeout, lookup.Sender, callbackData, depth+1)
}

func extractRPCErrorData(raw json.RawMessage) string {
	var direct string
	if json.Unmarshal(raw, &direct) == nil {
		return direct
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return ""
	}
	for _, key := range []string{"data", "result", "originalError"} {
		if value, ok := object[key]; ok {
			if encoded := extractRPCErrorData(value); encoded != "" {
				return encoded
			}
		}
	}
	return ""
}

func decodeOffchainLookup(value string) (offchainLookup, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if len(raw) < 8 || !strings.EqualFold(raw[:8], offchainLookupSelector) {
		return offchainLookup{}, errors.New("JSON-RPC error is not EIP-3668 OffchainLookup")
	}
	payload, err := hex.DecodeString(raw[8:])
	if err != nil || len(payload) < 160 {
		return offchainLookup{}, errors.New("invalid OffchainLookup ABI payload")
	}
	sender := "0x" + hex.EncodeToString(payload[12:32])
	urlsOffset, ok := abiOffset(payload[32:64], len(payload))
	if !ok {
		return offchainLookup{}, errors.New("invalid OffchainLookup URL offset")
	}
	callData, err := abiDynamicBytes(payload, payload[64:96])
	if err != nil {
		return offchainLookup{}, fmt.Errorf("invalid OffchainLookup callData: %w", err)
	}
	callback := append([]byte(nil), payload[96:100]...)
	extraData, err := abiDynamicBytes(payload, payload[128:160])
	if err != nil {
		return offchainLookup{}, fmt.Errorf("invalid OffchainLookup extraData: %w", err)
	}
	urls, err := abiStringArray(payload, urlsOffset)
	if err != nil {
		return offchainLookup{}, err
	}
	if len(urls) == 0 || len(urls) > 8 {
		return offchainLookup{}, errors.New("OffchainLookup must contain between 1 and 8 URLs")
	}
	return offchainLookup{
		Sender:           sender,
		URLs:             urls,
		CallData:         callData,
		CallbackFunction: callback,
		ExtraData:        extraData,
	}, nil
}

func abiStringArray(payload []byte, offset int) ([]string, error) {
	if offset+32 > len(payload) {
		return nil, errors.New("invalid OffchainLookup URL array")
	}
	count, ok := abiOffset(payload[offset:offset+32], 8)
	if !ok || count < 0 || count > 8 {
		return nil, errors.New("invalid OffchainLookup URL count")
	}
	base := offset + 32
	if base+count*32 > len(payload) {
		return nil, errors.New("truncated OffchainLookup URL array")
	}
	out := make([]string, 0, count)
	for index := 0; index < count; index++ {
		relative, ok := abiOffset(payload[base+index*32:base+(index+1)*32], len(payload)-base)
		if !ok {
			return nil, errors.New("invalid OffchainLookup URL offset")
		}
		value, err := abiBytesAt(payload, base+relative)
		if err != nil {
			return nil, errors.New("invalid OffchainLookup URL")
		}
		out = append(out, string(value))
	}
	return out, nil
}

func abiDynamicBytes(payload, offsetWord []byte) ([]byte, error) {
	offset, ok := abiOffset(offsetWord, len(payload))
	if !ok {
		return nil, errors.New("invalid dynamic offset")
	}
	return abiBytesAt(payload, offset)
}

func abiBytesAt(payload []byte, offset int) ([]byte, error) {
	if offset < 0 || offset+32 > len(payload) {
		return nil, errors.New("dynamic value exceeds payload")
	}
	length, ok := abiOffset(payload[offset:offset+32], len(payload)-offset-32)
	if !ok || offset+32+length > len(payload) {
		return nil, errors.New("dynamic value is truncated")
	}
	return append([]byte(nil), payload[offset+32:offset+32+length]...), nil
}

func abiOffset(word []byte, limit int) (int, bool) {
	if len(word) != 32 {
		return 0, false
	}
	value := 0
	for _, b := range word {
		if value > (limit-int(b))/256 {
			return 0, false
		}
		value = value*256 + int(b)
	}
	return value, value >= 0 && value <= limit
}

func fetchCCIPResponse(ctx context.Context, client *http.Client, lookup offchainLookup) ([]byte, error) {
	var failures []string
	for _, template := range lookup.URLs {
		response, err := fetchCCIPURL(ctx, client, template, lookup)
		if err == nil {
			return response, nil
		}
		failures = append(failures, err.Error())
	}
	return nil, fmt.Errorf("all CCIP-Read gateways failed: %s", strings.Join(failures, "; "))
}

func fetchCCIPURL(ctx context.Context, client *http.Client, template string, lookup offchainLookup) ([]byte, error) {
	dataHex := "0x" + hex.EncodeToString(lookup.CallData)
	target := strings.ReplaceAll(template, "{sender}", lookup.Sender)
	target = strings.ReplaceAll(target, "{data}", dataHex)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid CCIP-Read gateway URL")
	}
	if err := validateCCIPGateway(parsed); err != nil {
		return nil, err
	}
	var request *http.Request
	if strings.Contains(template, "{data}") {
		request, err = http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	} else {
		body, marshalErr := json.Marshal(map[string]string{"sender": lookup.Sender, "data": dataHex})
		if marshalErr != nil {
			return nil, marshalErr
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
		if err == nil {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "anyns-ccip-read/1")
	requestClient := *client
	originalRedirect := client.CheckRedirect
	requestClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if err := validateCCIPGateway(next.URL); err != nil {
			return fmt.Errorf("reject CCIP-Read redirect: %w", err)
		}
		if originalRedirect != nil {
			return originalRedirect(next, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	response, err := requestClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("CCIP-Read gateway status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCCIPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCCIPResponseBytes {
		return nil, errors.New("CCIP-Read gateway response exceeds 1 MiB")
	}
	var envelope struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errors.New("CCIP-Read gateway response must be JSON")
	}
	raw := strings.TrimPrefix(strings.TrimSpace(envelope.Data), "0x")
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("CCIP-Read gateway data must be non-empty hex")
	}
	return decoded, nil
}

func validateCCIPGateway(target *url.URL) error {
	scheme := strings.ToLower(target.Scheme)
	host := strings.ToLower(target.Hostname())
	loopbackTest := scheme == "http" && (host == "localhost" || isLoopbackHost(host))
	if scheme != "https" {
		if !loopbackTest {
			return errors.New("CCIP-Read gateway must use HTTPS; HTTP is allowed only for loopback tests")
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() && loopbackTest {
			return nil
		}
		if ip.IsPrivate() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("CCIP-Read gateway must not target a private, loopback, or link-local address")
		}
		return nil
	}
	if host == "localhost" {
		if loopbackTest {
			return nil
		}
		return errors.New("CCIP-Read gateway must not target localhost")
	}
	addresses, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve CCIP-Read gateway: %w", err)
	}
	for _, address := range addresses {
		if address.IsPrivate() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return errors.New("CCIP-Read gateway resolves to a private, loopback, or link-local address")
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func encodeCCIPCallback(selector, response, extraData []byte) string {
	head := make([]byte, 64)
	putABIUint(head[:32], 64)
	responseEncoded := encodeABIBytes(response)
	putABIUint(head[32:64], 64+len(responseEncoded))
	payload := append(append(head, responseEncoded...), encodeABIBytes(extraData)...)
	return "0x" + hex.EncodeToString(append(append([]byte(nil), selector...), payload...))
}

func encodeABIBytes(value []byte) []byte {
	padded := ((len(value) + 31) / 32) * 32
	out := make([]byte, 32+padded)
	putABIUint(out[:32], len(value))
	copy(out[32:], value)
	return out
}

func putABIUint(word []byte, value int) {
	encoded := strconv.FormatInt(int64(value), 16)
	if len(encoded)%2 != 0 {
		encoded = "0" + encoded
	}
	raw, _ := hex.DecodeString(encoded)
	copy(word[len(word)-len(raw):], raw)
}

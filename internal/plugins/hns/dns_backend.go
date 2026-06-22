package hns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/anyns/anyns/internal/dnsname"
	"github.com/anyns/anyns/internal/plugins"
)

const (
	maxDNSPacketSize     = 4096
	maxDNSNameWireLength = 255
)

type dnsExchangeFunc func(ctx context.Context, address string, packet []byte, wantID uint16) ([]byte, string, error)

var qtypeToCode = map[string]uint16{
	"A":       1,
	"NS":      2,
	"CNAME":   5,
	"SOA":     6,
	"MX":      15,
	"TXT":     16,
	"AAAA":    28,
	"SRV":     33,
	"DS":      43,
	"DNSKEY":  48,
	"TLSA":    52,
	"CAA":     257,
	"SVCB":    64,
	"HTTPS":   65,
	"WALLET":  262,
	"TYPE262": 262,
	"ANY":     255,
}

var codeToType = map[uint16]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	43:  "DS",
	48:  "DNSKEY",
	52:  "TLSA",
	64:  "SVCB",
	65:  "HTTPS",
	257: "CAA",
	262: "WALLET",
}

func (p *Plugin) resolveDNSBackend(ctx context.Context, req plugins.ResolveRequest, backendURL string, timeout time.Duration, started time.Time) (plugins.ResolveResult, error) {
	qtype := plugins.NormalizeQType(req.QType)
	qcode, ok := qtypeToCode[qtype]
	if !ok {
		res := plugins.NewResult(p.Name(), plugins.RCodeNoError, 60, nil, started)
		res.RawRecord["backend"] = "hns-dns"
		res.AuditMetadata["reason"] = "unsupported_dns_qtype"
		return res, nil
	}
	address, err := dnsBackendAddress(backendURL)
	if err != nil {
		return serviceFailure("dns_backend_url_invalid", started), err
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	originalName := plugins.NormalizeQName(req.QName)
	queryName, err := hnsDNSBackendQName(originalName)
	if err != nil {
		return serviceFailure("dns_query_name_invalid", started), err
	}
	packet, id, err := buildDNSQuery(queryName, qcode)
	if err != nil {
		return serviceFailure("dns_query_build_failed", started), err
	}
	exchange := p.dnsExchange
	if exchange == nil {
		exchange = exchangeDNS
	}
	response, transport, err := exchange(callCtx, address, packet, id)
	if err != nil {
		return serviceFailure("dns_backend_exchange_failed", started), err
	}
	result, err := parseDNSResponse(response, id, queryName, started)
	if err != nil {
		return serviceFailure("dns_backend_decode_failed", started), err
	}
	for i := range result.RRSet {
		result.RRSet[i].Name = restoreHNSDNSAnswerName(result.RRSet[i].Name, queryName, originalName)
	}
	result.SourcePlugin = p.Name()
	if result.RawRecord == nil {
		result.RawRecord = map[string]any{}
	}
	result.RawRecord["backend"] = "hns-dns"
	result.RawRecord["backend_addr"] = address
	result.RawRecord["backend_transport"] = transport
	result.RawRecord["backend_query_name"] = queryName
	if result.AuditMetadata == nil {
		result.AuditMetadata = map[string]any{}
	}
	result.AuditMetadata["backend_url"] = backendURL
	result.LatencyMS = time.Since(started).Milliseconds()
	return result, nil
}

func hnsDNSBackendQName(qname string) (string, error) {
	normalized := plugins.NormalizeQName(qname)
	for _, suffix := range []string{".hns.", ".hsd."} {
		if strings.HasSuffix(normalized, suffix) && len(normalized) > len(suffix) {
			normalized = strings.TrimSuffix(normalized, suffix) + "."
			break
		}
	}
	ascii, err := dnsname.ToASCII(normalized)
	if err != nil {
		return "", err
	}
	if err := validateHNSBackendRootLabel(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

func validateHNSBackendRootLabel(qname string) error {
	name := strings.TrimSuffix(qname, ".")
	if name == "" {
		return fmt.Errorf("HNS root label is required")
	}
	labels := strings.Split(name, ".")
	rootLabel := labels[len(labels)-1]
	if rootLabel == "" {
		return fmt.Errorf("HNS root label is required")
	}
	if strings.HasPrefix(rootLabel, "-") || strings.HasSuffix(rootLabel, "-") {
		return fmt.Errorf("HNS root label must not start or end with hyphen")
	}
	for _, character := range rootLabel {
		if character >= 'a' && character <= 'z' {
			continue
		}
		if character >= '0' && character <= '9' {
			continue
		}
		if character == '-' {
			continue
		}
		return fmt.Errorf("HNS root label must contain only letters, digits, and hyphen after IDNA normalization")
	}
	return nil
}

func restoreHNSDNSAnswerName(answerName, backendQName, originalQName string) string {
	answer := plugins.NormalizeQName(answerName)
	backend := plugins.NormalizeQName(backendQName)
	original := plugins.NormalizeQName(originalQName)
	if answer == backend {
		return original
	}
	backendBase := strings.TrimSuffix(backend, ".")
	if backendBase == "" {
		return answer
	}
	backendSuffix := "." + backendBase + "."
	if strings.HasSuffix(answer, backendSuffix) {
		prefix := strings.TrimSuffix(answer, backendSuffix)
		return prefix + "." + strings.TrimSuffix(original, ".") + "."
	}
	return answer
}

func exchangeDNS(ctx context.Context, address string, packet []byte, wantID uint16) ([]byte, string, error) {
	return exchangeDNSWith(ctx, address, packet, wantID, queryDNSUDP, queryDNSTCP)
}

func exchangeDNSWith(
	ctx context.Context,
	address string,
	packet []byte,
	wantID uint16,
	queryUDP func(context.Context, string, []byte) ([]byte, error),
	queryTCP func(context.Context, string, []byte) ([]byte, error),
) ([]byte, string, error) {
	response, err := queryUDP(ctx, address, packet)
	if err != nil {
		return nil, "udp", err
	}
	if dnsResponseTruncated(response, wantID) {
		response, err = queryTCP(ctx, address, packet)
		if err != nil {
			return nil, "tcp", err
		}
		return response, "tcp", nil
	}
	return response, "udp", nil
}

func queryDNSUDP(ctx context.Context, address string, packet []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func queryDNSTCP(ctx context.Context, address string, packet []byte) ([]byte, error) {
	if len(packet) > 65535 {
		return nil, errors.New("DNS query exceeds TCP length prefix limit")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var framed bytes.Buffer
	_ = binary.Write(&framed, binary.BigEndian, uint16(len(packet)))
	framed.Write(packet)
	if _, err := conn.Write(framed.Bytes()); err != nil {
		return nil, err
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[:]))
	if length == 0 || length > maxDNSPacketSize {
		return nil, fmt.Errorf("invalid DNS TCP response length %d", length)
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func dnsResponseTruncated(packet []byte, wantID uint16) bool {
	if len(packet) < 4 {
		return false
	}
	if binary.BigEndian.Uint16(packet[0:2]) != wantID {
		return false
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return flags&0x0200 != 0
}

func dnsBackendAddress(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(addr), "dns://") {
		return "", errors.New("dns backend URL must use dns scheme")
	}
	addr = strings.TrimSpace(addr[len("dns://"):])
	if addr == "" {
		return "", errors.New("dns backend address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if host == "" || port == "" {
			return "", errors.New("dns backend address must include host and port")
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Count(addr, ":") > 1 && !strings.HasPrefix(addr, "[") {
		return net.JoinHostPort(addr, "53"), nil
	}
	return net.JoinHostPort(addr, "53"), nil
}

func buildDNSQuery(qname string, qtype uint16) ([]byte, uint16, error) {
	id, err := randomDNSID()
	if err != nil {
		return nil, 0, err
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, id)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	if err := writeDNSName(&buf, qname); err != nil {
		return nil, 0, err
	}
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	return buf.Bytes(), id, nil
}

func randomDNSID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func writeDNSName(buf *bytes.Buffer, qname string) error {
	asciiName, err := dnsname.ToASCII(qname)
	if err != nil {
		return err
	}
	qname = strings.TrimSuffix(asciiName, ".")
	if qname == "" {
		buf.WriteByte(0)
		return nil
	}
	wireLen := 1
	for _, label := range strings.Split(qname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid DNS label %q", label)
		}
		wireLen += 1 + len(label)
		if wireLen > maxDNSNameWireLength {
			return errors.New("DNS name too long")
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	return nil
}

func parseDNSResponse(packet []byte, wantID uint16, qname string, started time.Time) (plugins.ResolveResult, error) {
	if len(packet) < 12 {
		return plugins.ResolveResult{}, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(packet[0:2]) != wantID {
		return plugins.ResolveResult{}, errors.New("DNS response id mismatch")
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	if flags&0x8000 == 0 {
		return plugins.ResolveResult{}, errors.New("DNS packet is not a response")
	}
	rcode := flags & 0x000f
	qdcount := int(binary.BigEndian.Uint16(packet[4:6]))
	ancount := int(binary.BigEndian.Uint16(packet[6:8]))
	if qdcount != 1 {
		return plugins.ResolveResult{}, errors.New("DNS response question count mismatch")
	}
	offset := 12
	normalizedQName := ""
	if qname != "" {
		normalizedQName = plugins.NormalizeQName(qname)
	}
	var err error
	for i := 0; i < qdcount; i++ {
		var questionName string
		questionName, offset, err = readDNSName(packet, offset)
		if err != nil {
			return plugins.ResolveResult{}, err
		}
		if offset+4 > len(packet) {
			return plugins.ResolveResult{}, errors.New("short DNS question")
		}
		if normalizedQName != "" && plugins.NormalizeQName(questionName) != normalizedQName {
			return plugins.ResolveResult{}, errors.New("DNS question name mismatch")
		}
		qclass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		if qclass != 1 {
			return plugins.ResolveResult{}, errors.New("DNS question class mismatch")
		}
		offset += 4
	}
	if rcode == 3 {
		res := plugins.NewResult("hns", plugins.RCodeNXDomain, 60, nil, started)
		res.AuditMetadata["reason"] = "dns_backend_nxdomain"
		return res, nil
	}
	if rcode != 0 {
		return plugins.ResolveResult{}, fmt.Errorf("dns backend rcode %d", rcode)
	}
	rrset := make([]plugins.RR, 0, ancount)
	ttl := 0
	for i := 0; i < ancount; i++ {
		var name string
		name, offset, err = readDNSName(packet, offset)
		if err != nil {
			return plugins.ResolveResult{}, err
		}
		if offset+10 > len(packet) {
			return plugins.ResolveResult{}, errors.New("short DNS RR header")
		}
		typ := binary.BigEndian.Uint16(packet[offset : offset+2])
		class := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		rrTTL := int(binary.BigEndian.Uint32(packet[offset+4 : offset+8]))
		rdlen := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(packet) {
			return plugins.ResolveResult{}, errors.New("short DNS RDATA")
		}
		rdataOffset := offset
		rdata := packet[offset : offset+rdlen]
		offset += rdlen
		if class != 1 {
			continue
		}
		normalizedName := plugins.NormalizeQName(name)
		if normalizedQName != "" && normalizedName != normalizedQName {
			continue
		}
		value, ok := formatRDATA(packet, rdataOffset, rdata, typ)
		if !ok {
			continue
		}
		rrType := codeToType[typ]
		if rrType == "" {
			rrType = "TYPE" + strconv.Itoa(int(typ))
		}
		rrset = append(rrset, plugins.RR{Name: normalizedName, Type: rrType, TTL: rrTTL, Value: value})
		if rrTTL > 0 && (ttl == 0 || rrTTL < ttl) {
			ttl = rrTTL
		}
	}
	if ttl == 0 {
		ttl = 60
	}
	res := plugins.NewResult("hns", plugins.RCodeNoError, ttl, rrset, started)
	if len(rrset) == 0 {
		res.AuditMetadata["reason"] = "dns_backend_nodata"
	}
	if normalizedQName != "" {
		res.RawRecord["query_name"] = normalizedQName
	}
	return res, nil
}

func formatRDATA(packet []byte, offset int, rdata []byte, typ uint16) (string, bool) {
	rdataEnd := offset + len(rdata)
	switch typ {
	case 1:
		if len(rdata) != net.IPv4len {
			return "", false
		}
		return net.IP(rdata).String(), true
	case 28:
		if len(rdata) != net.IPv6len {
			return "", false
		}
		return net.IP(rdata).String(), true
	case 2, 5:
		name, next, err := readDNSName(packet, offset)
		if err != nil || next > rdataEnd {
			return "", false
		}
		return plugins.NormalizeQName(name), true
	case 15:
		if len(rdata) < 3 {
			return "", false
		}
		pref := binary.BigEndian.Uint16(rdata[:2])
		name, next, err := readDNSName(packet, offset+2)
		if err != nil || next > rdataEnd {
			return "", false
		}
		return fmt.Sprintf("%d %s", pref, plugins.NormalizeQName(name)), true
	case 16:
		parts := []string{}
		for i := 0; i < len(rdata); {
			l := int(rdata[i])
			i++
			if i+l > len(rdata) {
				return "", false
			}
			parts = append(parts, string(rdata[i:i+l]))
			i += l
		}
		return strings.Join(parts, ""), true
	case 33:
		if len(rdata) < 7 {
			return "", false
		}
		priority := binary.BigEndian.Uint16(rdata[0:2])
		weight := binary.BigEndian.Uint16(rdata[2:4])
		port := binary.BigEndian.Uint16(rdata[4:6])
		target, next, err := readDNSName(packet, offset+6)
		if err != nil || next > rdataEnd {
			return "", false
		}
		return fmt.Sprintf("%d %d %d %s", priority, weight, port, plugins.NormalizeQName(target)), true
	case 43:
		if len(rdata) < 4 {
			return "", false
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rdata[0:2]), rdata[2], rdata[3], strings.ToUpper(hex.EncodeToString(rdata[4:]))), true
	case 48:
		if len(rdata) < 4 {
			return "", false
		}
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(rdata[0:2]), rdata[2], rdata[3], base64.StdEncoding.EncodeToString(rdata[4:])), true
	case 52:
		if len(rdata) < 3 {
			return "", false
		}
		return fmt.Sprintf("%d %d %d %s", rdata[0], rdata[1], rdata[2], strings.ToUpper(hex.EncodeToString(rdata[3:]))), true
	case 257:
		if len(rdata) < 2 {
			return "", false
		}
		tagLen := int(rdata[1])
		if 2+tagLen > len(rdata) {
			return "", false
		}
		return fmt.Sprintf("%d %s %q", rdata[0], string(rdata[2:2+tagLen]), string(rdata[2+tagLen:])), true
	default:
		return fmt.Sprintf(`\# %d %s`, len(rdata), strings.ToUpper(hex.EncodeToString(rdata))), true
	}
}

func readDNSName(packet []byte, offset int) (string, int, error) {
	labels := []string{}
	next := offset
	jumped := false
	seen := 0
	wireLen := 1
	for {
		if offset >= len(packet) {
			return "", 0, errors.New("DNS name exceeds packet")
		}
		length := int(packet[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(packet) {
				return "", 0, errors.New("short DNS compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3fff)
			if ptr >= len(packet) {
				return "", 0, errors.New("DNS compression pointer out of range")
			}
			if !jumped {
				next = offset + 2
			}
			offset = ptr
			jumped = true
			seen++
			if seen > len(packet) {
				return "", 0, errors.New("DNS compression pointer loop")
			}
			continue
		}
		if length&0xc0 != 0 {
			return "", 0, errors.New("unsupported DNS label encoding")
		}
		offset++
		if length == 0 {
			if !jumped {
				next = offset
			}
			if len(labels) == 0 {
				return ".", next, nil
			}
			return strings.Join(labels, ".") + ".", next, nil
		}
		if offset+length > len(packet) {
			return "", 0, errors.New("short DNS label")
		}
		wireLen += 1 + length
		if wireLen > maxDNSNameWireLength {
			return "", 0, errors.New("DNS name too long")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
}

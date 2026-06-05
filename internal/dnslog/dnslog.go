package dnslog

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Timestamp    time.Time      `json:"timestamp"`
	TraceID      string         `json:"trace_id"`
	ClientIP     string         `json:"client_ip"`
	ClientView   string         `json:"client_view"`
	Tenant       string         `json:"tenant"`
	QName        string         `json:"qname"`
	QType        string         `json:"qtype"`
	RCode        string         `json:"rcode"`
	Answer       []string       `json:"answer"`
	SourcePlugin string         `json:"source_plugin"`
	RiskLevel    string         `json:"risk_level"`
	Action       string         `json:"action"`
	MatchedRule  string         `json:"matched_rule"`
	RawRR        map[string]any `json:"raw_rr,omitempty"`
	LatencyMS    int64          `json:"latency_ms"`
}

type Store struct {
	mu      sync.RWMutex
	events  []Event
	limit   int
	path    string
	lastErr error
}

type EventFilter struct {
	TraceID       string
	ClientIP      string
	ClientView    string
	Tenant        string
	QName         string
	QNameContains string
	QType         string
	SourcePlugin  string
	RiskLevel     string
	Action        string
	MatchedRule   string
	RCode         string
	Since         time.Time
	Until         time.Time
	Order         string
}

type EventPage struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

type Summary struct {
	Total           int                     `json:"total"`
	ByRiskLevel     map[string]int          `json:"by_risk_level"`
	ByAction        map[string]int          `json:"by_action"`
	ByRule          map[string]int          `json:"by_rule"`
	ByPlugin        map[string]int          `json:"by_plugin"`
	ByRCode         map[string]int          `json:"by_rcode"`
	LatencyMS       LatencySummary          `json:"latency_ms"`
	LatencyByPlugin map[string]LatencyStats `json:"latency_by_plugin_ms"`
	TopClients      []TopValue              `json:"top_clients"`
	TopQNames       []TopValue              `json:"top_qnames"`
}

type TopValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type LatencySummary struct {
	Count   int `json:"count"`
	Average int `json:"average"`
	Max     int `json:"max"`
}

type LatencyStats struct {
	Count   int `json:"count"`
	Sum     int `json:"-"`
	Average int `json:"average"`
	Max     int `json:"max"`
}

func NewStore(limit int) *Store {
	if limit <= 0 {
		limit = 1000
	}
	return &Store{limit: limit}
}

func NewPersistentStore(limit int, path string) (*Store, error) {
	store := NewStore(limit)
	store.path = path
	if path == "" {
		return store, nil
	}
	if err := store.load(); err != nil {
		return store, err
	}
	return store, nil
}

func (s *Store) Append(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	if len(s.events) > s.limit {
		copy(s.events, s.events[len(s.events)-s.limit:])
		s.events = s.events[:s.limit]
	}
	if s.path != "" {
		s.lastErr = appendJSONLine(s.path, event)
	}
}

func (s *Store) List(limit int) []Event {
	return s.ListFiltered(EventFilter{}, limit)
}

func (s *Store) ListFiltered(filter EventFilter, limit int) []Event {
	events := s.filteredOrderedEvents(filter)
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}
	if filter.Order == "" {
		start := len(events) - limit
		out := make([]Event, limit)
		copy(out, events[start:])
		return out
	}
	out := make([]Event, limit)
	copy(out, events[:limit])
	return out
}

func (s *Store) ListFilteredPage(filter EventFilter, limit int, cursor string) EventPage {
	events := s.filteredOrderedEvents(filter)
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	offset := parseCursor(cursor)
	if offset > len(events) {
		offset = len(events)
	}
	end := offset + limit
	if end > len(events) {
		end = len(events)
	}
	out := make([]Event, end-offset)
	copy(out, events[offset:end])
	page := EventPage{Events: out}
	if end < len(events) {
		page.NextCursor = strconv.Itoa(end)
	}
	return page
}

func (s *Store) filteredOrderedEvents(filter EventFilter) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]Event, 0, len(s.events))
	for _, event := range s.events {
		if filter.Matches(event) {
			events = append(events, event)
		}
	}
	if filter.Order == "desc" {
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
	}
	return events
}

func parseCursor(cursor string) int {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 0
	}
	offset, err := strconv.Atoi(cursor)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func (f EventFilter) Matches(event Event) bool {
	if !f.Since.IsZero() && event.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && event.Timestamp.After(f.Until) {
		return false
	}
	if f.TraceID != "" && event.TraceID != f.TraceID {
		return false
	}
	if f.ClientIP != "" && event.ClientIP != f.ClientIP {
		return false
	}
	if f.ClientView != "" && event.ClientView != f.ClientView {
		return false
	}
	if f.Tenant != "" && event.Tenant != f.Tenant {
		return false
	}
	if f.QName != "" && event.QName != f.QName {
		return false
	}
	if f.QNameContains != "" && !strings.Contains(strings.ToLower(event.QName), strings.ToLower(f.QNameContains)) {
		return false
	}
	if f.QType != "" && event.QType != f.QType {
		return false
	}
	if f.SourcePlugin != "" && event.SourcePlugin != f.SourcePlugin {
		return false
	}
	if f.RiskLevel != "" && event.RiskLevel != f.RiskLevel {
		return false
	}
	if f.Action != "" && event.Action != f.Action {
		return false
	}
	if f.MatchedRule != "" && event.MatchedRule != f.MatchedRule {
		return false
	}
	if f.RCode != "" && event.RCode != f.RCode {
		return false
	}
	return true
}

func (s *Store) Summary(topN int) Summary {
	events := s.List(0)
	summary := Summary{
		Total:           len(events),
		ByRiskLevel:     map[string]int{},
		ByAction:        map[string]int{},
		ByRule:          map[string]int{},
		ByPlugin:        map[string]int{},
		ByRCode:         map[string]int{},
		LatencyByPlugin: map[string]LatencyStats{},
	}
	clients := map[string]int{}
	qnames := map[string]int{}
	var latencySum int
	for _, event := range events {
		increment(summary.ByRiskLevel, event.RiskLevel)
		increment(summary.ByAction, event.Action)
		increment(summary.ByRule, event.MatchedRule)
		increment(summary.ByPlugin, event.SourcePlugin)
		increment(summary.ByRCode, event.RCode)
		increment(clients, event.ClientIP)
		increment(qnames, event.QName)
		latency := int(event.LatencyMS)
		if latency < 0 {
			latency = 0
		}
		summary.LatencyMS.Count++
		latencySum += latency
		if latency > summary.LatencyMS.Max {
			summary.LatencyMS.Max = latency
		}
		plugin := event.SourcePlugin
		if plugin == "" {
			plugin = "unknown"
		}
		stats := summary.LatencyByPlugin[plugin]
		stats.Count++
		stats.Sum += latency
		if latency > stats.Max {
			stats.Max = latency
		}
		stats.Average = stats.Sum / stats.Count
		summary.LatencyByPlugin[plugin] = stats
	}
	if summary.LatencyMS.Count > 0 {
		summary.LatencyMS.Average = latencySum / summary.LatencyMS.Count
	}
	summary.TopClients = topValues(clients, topN)
	summary.TopQNames = topValues(qnames, topN)
	return summary
}

func (s *Store) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

func (s *Store) load() error {
	file, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return err
		}
		s.events = append(s.events, event)
		if len(s.events) > s.limit {
			copy(s.events, s.events[len(s.events)-s.limit:])
			s.events = s.events[:s.limit]
		}
	}
	return scanner.Err()
}

func appendJSONLine(path string, value any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}

func increment(counts map[string]int, key string) {
	if key == "" {
		key = "unknown"
	}
	counts[key]++
}

func topValues(counts map[string]int, limit int) []TopValue {
	if limit <= 0 {
		limit = 10
	}
	values := make([]TopValue, 0, len(counts))
	for value, count := range counts {
		values = append(values, TopValue{Value: value, Count: count})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count == values[j].Count {
			return values[i].Value < values[j].Value
		}
		return values[i].Count > values[j].Count
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values
}

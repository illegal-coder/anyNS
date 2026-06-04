package honeypot

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/anyns/anyns/internal/dnslog"
)

type Client struct {
	mu            sync.RWMutex
	URL           string
	APIKey        string
	HMACSecret    string
	HTTPClient    *http.Client
	Queue         *FailedQueue
	MaxAttempts   int
	RetryInterval time.Duration
	Attempted     int
	Delivered     int
	LastAttemptAt time.Time
	LastError     string
	LastLatency   time.Duration
	Retained      int
	Dropped       int
}

type DeliveryStatus struct {
	Enabled                bool      `json:"enabled"`
	LastAttemptAt          time.Time `json:"last_attempt_at,omitempty"`
	LastError              string    `json:"last_error,omitempty"`
	LastLatencyMS          int64     `json:"last_latency_ms"`
	Attempted              int       `json:"attempted"`
	Delivered              int       `json:"delivered"`
	Retained               int       `json:"retained"`
	Dropped                int       `json:"dropped"`
	FailedQueueLength      int       `json:"failed_queue_length"`
	OldestQueuedAt         time.Time `json:"oldest_queued_at,omitempty"`
	OldestQueuedAgeSeconds int       `json:"oldest_queued_age_seconds"`
}

type DrainResult struct {
	Attempted int    `json:"attempted"`
	Delivered int    `json:"delivered"`
	Retained  int    `json:"retained"`
	Dropped   int    `json:"dropped"`
	LastError string `json:"last_error,omitempty"`
}

type ReplayWorkerOptions struct {
	Interval time.Duration
	Limit    int
	Logf     func(format string, args ...any)
}

type FailedDelivery struct {
	QueuedAt  time.Time      `json:"queued_at"`
	Attempts  int            `json:"attempts"`
	LastError string         `json:"last_error"`
	Events    []dnslog.Event `json:"events"`
}

type FailedQueue struct {
	mu      sync.RWMutex
	path    string
	max     int
	entries []FailedDelivery
}

type requestBody struct {
	Events []dnslog.Event `json:"events"`
}

func (c *Client) Deliver(ctx context.Context, events []dnslog.Event) error {
	started := time.Now()
	if c.URL == "" {
		err := errors.New("honeypot url is empty")
		c.recordAttempt(started, err)
		return err
	}
	body, err := json.Marshal(requestBody{Events: events})
	if err != nil {
		c.recordAttempt(started, err)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		c.recordAttempt(started, err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.HMACSecret != "" {
		req.Header.Set("X-anyNS-Signature", Sign(body, c.HMACSecret))
	}
	if len(events) > 0 && events[0].TraceID != "" {
		req.Header.Set("X-anyNS-Idempotency-Key", events[0].TraceID)
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		c.recordAttempt(started, err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("honeypot returned HTTP %d", resp.StatusCode)
		c.recordAttempt(started, err)
		return err
	}
	c.recordAttempt(started, nil)
	return nil
}

func (c *Client) DeliverOrQueue(ctx context.Context, events []dnslog.Event) error {
	err := c.Deliver(ctx, events)
	if err == nil || c.Queue == nil {
		return err
	}
	queueErr := c.Queue.Enqueue(FailedDelivery{
		QueuedAt:  time.Now().UTC(),
		Attempts:  1,
		LastError: err.Error(),
		Events:    events,
	})
	if queueErr != nil {
		return fmt.Errorf("%w; failed to queue delivery: %v", err, queueErr)
	}
	return err
}

func (c *Client) Drain(ctx context.Context, limit int) (DrainResult, error) {
	if c.Queue == nil {
		return DrainResult{}, errors.New("honeypot failed queue is not configured")
	}
	if c.URL == "" {
		return DrainResult{}, errors.New("honeypot url is empty")
	}
	if limit <= 0 {
		limit = c.Queue.Len()
	}
	maxAttempts := c.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	result, err := c.Queue.Drain(ctx, limit, maxAttempts, func(ctx context.Context, delivery FailedDelivery) error {
		return c.Deliver(ctx, delivery.Events)
	})
	c.recordDrain(result, err)
	return result, err
}

func (c *Client) Status(now time.Time) DeliveryStatus {
	c.mu.RLock()
	status := DeliveryStatus{
		Enabled:       c.URL != "",
		LastAttemptAt: c.LastAttemptAt,
		LastError:     c.LastError,
		LastLatencyMS: c.LastLatency.Milliseconds(),
		Attempted:     c.Attempted,
		Delivered:     c.Delivered,
		Retained:      c.Retained,
		Dropped:       c.Dropped,
	}
	c.mu.RUnlock()
	if c.Queue != nil {
		status.FailedQueueLength = c.Queue.Len()
		status.OldestQueuedAt = c.Queue.OldestQueuedAt()
		if !status.OldestQueuedAt.IsZero() {
			if now.IsZero() {
				now = time.Now().UTC()
			}
			status.OldestQueuedAgeSeconds = int(now.Sub(status.OldestQueuedAt).Seconds())
			if status.OldestQueuedAgeSeconds < 0 {
				status.OldestQueuedAgeSeconds = 0
			}
		}
	}
	return status
}

func (c *Client) recordAttempt(started time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Attempted++
	c.LastAttemptAt = time.Now().UTC()
	c.LastLatency = time.Since(started)
	if err != nil {
		c.LastError = err.Error()
		return
	}
	c.Delivered++
	c.LastError = ""
}

func (c *Client) recordDrain(result DrainResult, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Retained += result.Retained
	c.Dropped += result.Dropped
	if err != nil {
		c.LastError = err.Error()
		return
	}
	if result.LastError != "" {
		c.LastError = result.LastError
	}
}

func (c *Client) StartReplayWorker(ctx context.Context, opts ReplayWorkerOptions) <-chan DrainResult {
	results := make(chan DrainResult, 1)
	interval := opts.Interval
	if interval <= 0 {
		interval = c.RetryInterval
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		defer close(results)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		c.drainForWorker(ctx, opts, results)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.drainForWorker(ctx, opts, results)
			}
		}
	}()
	return results
}

func (c *Client) drainForWorker(ctx context.Context, opts ReplayWorkerOptions, results chan<- DrainResult) {
	if c.Queue == nil || c.Queue.Len() == 0 || c.URL == "" {
		return
	}
	result, err := c.Drain(ctx, opts.Limit)
	if err != nil {
		result.LastError = err.Error()
	}
	if opts.Logf != nil && (err != nil || result.Attempted > 0) {
		opts.Logf("honeypot replay attempted=%d delivered=%d retained=%d dropped=%d error=%s", result.Attempted, result.Delivered, result.Retained, result.Dropped, result.LastError)
	}
	select {
	case results <- result:
	default:
	}
}

func NewFailedQueue(path string, maxEntries int) (*FailedQueue, error) {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	q := &FailedQueue{path: path, max: maxEntries}
	if path == "" {
		return q, nil
	}
	if err := q.load(); err != nil {
		return q, err
	}
	return q, nil
}

func (q *FailedQueue) Enqueue(delivery FailedDelivery) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if delivery.QueuedAt.IsZero() {
		delivery.QueuedAt = time.Now().UTC()
	}
	q.entries = append(q.entries, delivery)
	if len(q.entries) > q.max {
		copy(q.entries, q.entries[len(q.entries)-q.max:])
		q.entries = q.entries[:q.max]
	}
	if q.path == "" {
		return nil
	}
	file, err := os.OpenFile(q.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	encoded, err := json.Marshal(delivery)
	if err != nil {
		return err
	}
	_, err = file.Write(append(encoded, '\n'))
	return err
}

func (q *FailedQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries)
}

func (q *FailedQueue) List(limit int) []FailedDelivery {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if limit <= 0 || limit > len(q.entries) {
		limit = len(q.entries)
	}
	start := len(q.entries) - limit
	out := make([]FailedDelivery, limit)
	copy(out, q.entries[start:])
	return out
}

func (q *FailedQueue) OldestQueuedAt() time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if len(q.entries) == 0 {
		return time.Time{}
	}
	oldest := q.entries[0].QueuedAt
	for _, entry := range q.entries[1:] {
		if !entry.QueuedAt.IsZero() && (oldest.IsZero() || entry.QueuedAt.Before(oldest)) {
			oldest = entry.QueuedAt
		}
	}
	return oldest
}

func (q *FailedQueue) Drain(ctx context.Context, limit int, maxAttempts int, deliver func(context.Context, FailedDelivery) error) (DrainResult, error) {
	q.mu.RLock()
	if limit <= 0 || limit > len(q.entries) {
		limit = len(q.entries)
	}
	selected := make([]FailedDelivery, limit)
	copy(selected, q.entries[:limit])
	q.mu.RUnlock()

	result := DrainResult{}
	retained := make([]FailedDelivery, 0, len(selected))
	for _, delivery := range selected {
		if ctx.Err() != nil {
			result.LastError = ctx.Err().Error()
			retained = append(retained, delivery)
			continue
		}
		delivery.Attempts++
		result.Attempted++
		err := deliver(ctx, delivery)
		if err == nil {
			result.Delivered++
			continue
		}
		delivery.LastError = err.Error()
		result.LastError = err.Error()
		if maxAttempts > 0 && delivery.Attempts >= maxAttempts {
			result.Dropped++
			continue
		}
		result.Retained++
		retained = append(retained, delivery)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.entries) < len(selected) {
		q.entries = retained
	} else {
		remaining := append([]FailedDelivery(nil), q.entries[len(selected):]...)
		q.entries = append(retained, remaining...)
	}
	if q.path == "" {
		return result, nil
	}
	if err := q.rewriteLocked(); err != nil {
		return result, err
	}
	return result, nil
}

func (q *FailedQueue) load() error {
	file, err := os.Open(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var delivery FailedDelivery
		if err := json.Unmarshal(scanner.Bytes(), &delivery); err != nil {
			return err
		}
		q.entries = append(q.entries, delivery)
		if len(q.entries) > q.max {
			copy(q.entries, q.entries[len(q.entries)-q.max:])
			q.entries = q.entries[:q.max]
		}
	}
	return scanner.Err()
}

func (q *FailedQueue) rewriteLocked() error {
	file, err := os.OpenFile(q.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, delivery := range q.entries {
		encoded, err := json.Marshal(delivery)
		if err != nil {
			return err
		}
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

package honeypot

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anyns/anyns/internal/dnslog"
)

func TestSign(t *testing.T) {
	got := Sign([]byte(`{"events":[]}`), "secret")
	want := "sha256=a642b59553c93e227ec0f2f38910fbf71231a2197c00899833c00478cec86f34"
	if got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestDeliverOrQueuePersistsFailedDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed.jsonl")
	queue, err := NewFailedQueue(path, 10)
	if err != nil {
		t.Fatalf("new failed queue: %v", err)
	}
	client := &Client{URL: "://bad-url", Queue: queue}
	err = client.DeliverOrQueue(context.Background(), []dnslog.Event{{
		Timestamp: time.Unix(1, 0).UTC(),
		TraceID:   "trace-failed",
		QName:     "bad.example.",
		QType:     "TXT",
	}})
	if err == nil {
		t.Fatalf("expected delivery error")
	}
	if queue.Len() != 1 {
		t.Fatalf("queue len = %d, want 1", queue.Len())
	}
	reloaded, err := NewFailedQueue(path, 10)
	if err != nil {
		t.Fatalf("reload failed queue: %v", err)
	}
	items := reloaded.List(0)
	if len(items) != 1 || len(items[0].Events) != 1 || items[0].Events[0].TraceID != "trace-failed" {
		t.Fatalf("unexpected queued delivery: %#v", items)
	}
}

func TestDrainDeliversAndRemovesPersistedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "failed.jsonl")
	queue, err := NewFailedQueue(path, 10)
	if err != nil {
		t.Fatalf("new failed queue: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{QueuedAt: time.Unix(1, 0).UTC(), Attempts: 1, Events: []dnslog.Event{{TraceID: "one"}}}); err != nil {
		t.Fatalf("enqueue one: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{QueuedAt: time.Unix(2, 0).UTC(), Attempts: 1, Events: []dnslog.Event{{TraceID: "two"}}}); err != nil {
		t.Fatalf("enqueue two: %v", err)
	}
	client := &Client{
		URL:         "https://honeypot.example/api/v1/dns-events",
		Queue:       queue,
		MaxAttempts: 3,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		})},
	}
	result, err := client.Drain(context.Background(), 1)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Attempted != 1 || result.Delivered != 1 || result.Retained != 0 || result.Dropped != 0 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	if queue.Len() != 1 || queue.List(0)[0].Events[0].TraceID != "two" {
		t.Fatalf("queue after drain: %#v", queue.List(0))
	}
	reloaded, err := NewFailedQueue(path, 10)
	if err != nil {
		t.Fatalf("reload queue: %v", err)
	}
	if reloaded.Len() != 1 || reloaded.List(0)[0].Events[0].TraceID != "two" {
		t.Fatalf("persisted queue after drain: %#v", reloaded.List(0))
	}
}

func TestDrainRetainsOrDropsFailuresByMaxAttempts(t *testing.T) {
	queue, err := NewFailedQueue("", 10)
	if err != nil {
		t.Fatalf("new failed queue: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{Attempts: 1, Events: []dnslog.Event{{TraceID: "retain"}}}); err != nil {
		t.Fatalf("enqueue retain: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{Attempts: 2, Events: []dnslog.Event{{TraceID: "drop"}}}); err != nil {
		t.Fatalf("enqueue drop: %v", err)
	}
	client := &Client{
		URL:         "https://honeypot.example/api/v1/dns-events",
		Queue:       queue,
		MaxAttempts: 3,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(`bad gateway`)), Header: make(http.Header)}, nil
		})},
	}
	result, err := client.Drain(context.Background(), 0)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if result.Attempted != 2 || result.Delivered != 0 || result.Retained != 1 || result.Dropped != 1 {
		t.Fatalf("unexpected drain result: %#v", result)
	}
	items := queue.List(0)
	if len(items) != 1 || items[0].Events[0].TraceID != "retain" || items[0].Attempts != 2 {
		t.Fatalf("queue after failed drain: %#v", items)
	}
	status := client.Status(time.Unix(10, 0).UTC())
	if status.Retained != 1 || status.Dropped != 1 {
		t.Fatalf("status retained/dropped = %#v", status)
	}
}

func TestStatusReportsDeliveryAndQueueAge(t *testing.T) {
	queue, err := NewFailedQueue("", 10)
	if err != nil {
		t.Fatalf("new failed queue: %v", err)
	}
	oldest := time.Unix(100, 0).UTC()
	if err := queue.Enqueue(FailedDelivery{QueuedAt: oldest.Add(10 * time.Second), Events: []dnslog.Event{{TraceID: "newer"}}}); err != nil {
		t.Fatalf("enqueue newer: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{QueuedAt: oldest, Events: []dnslog.Event{{TraceID: "oldest"}}}); err != nil {
		t.Fatalf("enqueue oldest: %v", err)
	}
	client := &Client{
		URL:   "https://honeypot.example/api/v1/dns-events",
		Queue: queue,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		})},
	}
	if err := client.Deliver(context.Background(), []dnslog.Event{{TraceID: "delivered"}}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	status := client.Status(oldest.Add(70 * time.Second))
	if !status.Enabled || status.Attempted != 1 || status.Delivered != 1 || status.LastError != "" {
		t.Fatalf("unexpected delivery status: %#v", status)
	}
	if status.FailedQueueLength != 2 || !status.OldestQueuedAt.Equal(oldest) || status.OldestQueuedAgeSeconds != 70 {
		t.Fatalf("unexpected queue status: %#v", status)
	}
}

func TestStartReplayWorkerDrainsQueuedDeliveries(t *testing.T) {
	queue, err := NewFailedQueue("", 10)
	if err != nil {
		t.Fatalf("new failed queue: %v", err)
	}
	if err := queue.Enqueue(FailedDelivery{Attempts: 1, Events: []dnslog.Event{{TraceID: "queued"}}}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	client := &Client{
		URL:           "https://honeypot.example/api/v1/dns-events",
		Queue:         queue,
		MaxAttempts:   3,
		RetryInterval: time.Hour,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		})},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := client.StartReplayWorker(ctx, ReplayWorkerOptions{Interval: time.Hour, Limit: 1})
	select {
	case result := <-results:
		if result.Attempted != 1 || result.Delivered != 1 {
			t.Fatalf("unexpected replay result: %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for replay result")
	}
	if queue.Len() != 0 {
		t.Fatalf("queue len after replay = %d, want 0", queue.Len())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

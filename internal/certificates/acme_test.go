package certificates

import (
	"errors"
	"net/url"
	"testing"
)

func TestSelectFinalizeURLPreservesCreatedOrderURL(t *testing.T) {
	got, err := selectFinalizeURL("https://ca.test/order/1/finalize", "")
	if err != nil {
		t.Fatalf("select finalize URL: %v", err)
	}
	if got != "https://ca.test/order/1/finalize" {
		t.Fatalf("finalize URL = %q", got)
	}
}

func TestSelectFinalizeURLPrefersRefreshedOrderURL(t *testing.T) {
	got, err := selectFinalizeURL("https://ca.test/order/1/finalize", "https://ca.test/order/2/finalize")
	if err != nil {
		t.Fatalf("select finalize URL: %v", err)
	}
	if got != "https://ca.test/order/2/finalize" {
		t.Fatalf("finalize URL = %q", got)
	}
}

func TestSelectFinalizeURLRejectsMissingURL(t *testing.T) {
	if _, err := selectFinalizeURL("", ""); err == nil {
		t.Fatal("expected missing finalize URL error")
	}
}

func TestIsEmptyACMEPollURLError(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "", Err: errors.New("unsupported protocol scheme")}
	if !isEmptyACMEPollURLError(err) {
		t.Fatal("expected empty ACME poll URL error to be recognized")
	}
	if isEmptyACMEPollURLError(&url.Error{Op: "Post", URL: "https://ca.test/order/1", Err: errors.New("timeout")}) {
		t.Fatal("non-empty ACME URL must not trigger recovery")
	}
	if isEmptyACMEPollURLError(errors.New("unrelated")) {
		t.Fatal("unrelated error must not trigger recovery")
	}
}

package enzonix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdk "github.com/Enzonix-LLC/dns-sdk-go"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	cfg := `
enzonix {
	api_key test-key
	endpoint https://edge.enzonix.test/api
	timeout 5s
}
`
	d := caddyfile.NewTestDispenser(cfg)

	var p Provider
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.APIKey != "test-key" {
		t.Fatalf("APIKey not set: %s", p.APIKey)
	}
	if p.APIEndpoint != "https://edge.enzonix.test/api" {
		t.Fatalf("APIEndpoint mismatch: %s", p.APIEndpoint)
	}
	if time.Duration(p.Timeout) != 5*time.Second {
		t.Fatalf("Timeout mismatch: %v", p.Timeout)
	}
}

func TestGetRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/client/domains":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "dom-1", "name": "example.com"},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/client/domains/dom-1/records":
			if got := r.Header.Get("Authorization"); got != "Bearer key" {
				t.Fatalf("expected auth header, got %q", got)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "1", "type": "A", "name": "www", "value": "1.2.3.4", "ttl": 60},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	sdkClient, err := sdk.NewClient("key", sdk.WithBaseURL(server.URL), sdk.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("sdk setup error: %v", err)
	}

	p := Provider{
		APIKey:      "key",
		APIEndpoint: server.URL,
		Timeout:     caddyDuration(2 * time.Second),
		client:      sdkClient,
		logger:      zap.NewNop(),
	}

	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("unexpected record count: %d", len(recs))
	}
	rr := recs[0].RR()
	if rr.Data != "1.2.3.4" || rr.Name != "www" {
		t.Fatalf("unexpected records: %#v", recs)
	}
}

func TestAppendRecords(t *testing.T) {
	var received sdk.CreateRecordRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/client/domains":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": "dom-1", "name": "example.com"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/client/records":
			if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
				t.Fatalf("decode received: %v", err)
			}
			_ = json.NewEncoder(w).Encode(enzonixRecordFromCreate(received))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	sdkClient, err := sdk.NewClient("key", sdk.WithBaseURL(server.URL), sdk.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("sdk setup error: %v", err)
	}

	p := Provider{
		APIKey:      "key",
		APIEndpoint: server.URL,
		Timeout:     caddyDuration(2 * time.Second),
		client:      sdkClient,
		logger:      zap.NewNop(),
	}

	input := []libdns.Record{
		libdns.TXT{
			Name: "_acme-challenge",
			Text: "token",
			TTL:  120 * time.Second,
		},
	}

	recs, err := p.AppendRecords(context.Background(), "example.com.", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("unexpected record count: %d", len(recs))
	}
	rr := recs[0].RR()
	if rr.TTL != 120*time.Second {
		t.Fatalf("unexpected records response: %#v", recs)
	}
	if received.TTL == nil || *received.TTL != 120 {
		t.Fatalf("unexpected payload ttl: %#v", received)
	}
	if received.DomainID != "dom-1" {
		t.Fatalf("unexpected domain id: %s", received.DomainID)
	}
}

func TestDeleteRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE got %s", r.Method)
		}
		if r.URL.Path != "/api/client/records/abc" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sdkClient, err := sdk.NewClient("key", sdk.WithBaseURL(server.URL), sdk.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("sdk setup error: %v", err)
	}

	p := Provider{
		APIKey:      "key",
		APIEndpoint: server.URL,
		Timeout:     caddyDuration(2 * time.Second),
		client:      sdkClient,
		logger:      zap.NewNop(),
	}

	input := []libdns.Record{
		recordWithID{
			rr: libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge",
				Data: "token",
			},
			ID: "abc",
		},
	}

	if _, err := p.DeleteRecords(context.Background(), "example.com.", input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT got %s", r.Method)
		}
		if r.URL.Path != "/api/client/records/1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload sdk.UpdateRecordRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode received: %v", err)
		}
		_ = json.NewEncoder(w).Encode(enzonixRecordFromUpdate("1", payload))
	}))
	defer server.Close()

	sdkClient, err := sdk.NewClient("key", sdk.WithBaseURL(server.URL), sdk.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("sdk setup error: %v", err)
	}

	p := Provider{
		APIKey:      "key",
		APIEndpoint: server.URL,
		Timeout:     caddyDuration(2 * time.Second),
		client:      sdkClient,
		logger:      zap.NewNop(),
	}

	input := []libdns.Record{
		recordWithID{
			rr: libdns.RR{
				Type: "A",
				Name: "www",
				Data: "1.1.1.1",
				TTL:  30 * time.Second,
			},
			ID: "1",
		},
	}

	recs, err := p.SetRecords(context.Background(), "example.com.", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recs) != 1 {
		t.Fatalf("unexpected record count: %d", len(recs))
	}
	rr := recs[0].RR()
	if rr.Data != "1.1.1.1" {
		t.Fatalf("unexpected response: %#v", recs)
	}
}

func caddyDuration(d time.Duration) caddy.Duration { return caddy.Duration(d) }

func enzonixRecordFromCreate(req sdk.CreateRecordRequest) map[string]any {
	ttl := 0
	if req.TTL != nil {
		ttl = *req.TTL
	}

	return map[string]any{
		"id":        "generated",
		"domain_id": req.DomainID,
		"name":      req.Name,
		"type":      req.Type,
		"value":     req.Value,
		"ttl":       ttl,
	}
}

func enzonixRecordFromUpdate(id string, req sdk.UpdateRecordRequest) map[string]any {
	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	typ := ""
	if req.Type != nil {
		typ = *req.Type
	}
	value := ""
	if req.Value != nil {
		value = *req.Value
	}
	ttl := 0
	if req.TTL != nil {
		ttl = *req.TTL
	}

	return map[string]any{
		"id":    id,
		"name":  name,
		"type":  typ,
		"value": value,
		"ttl":   ttl,
	}
}

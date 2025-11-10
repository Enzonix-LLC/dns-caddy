package enzonix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	sdk "github.com/Enzonix-LLC/dns-sdk-go"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

const (
	defaultTimeout = 10 * time.Second
)

// Provider implements the libdns interfaces for Enzonix.
type Provider struct {
	APIKey      string         `json:"api_key,omitempty"`
	APIEndpoint string         `json:"api_endpoint,omitempty"`
	Timeout     caddy.Duration `json:"timeout,omitempty"`

	client *sdk.Client
	logger *zap.Logger
}

// Ensure Provider conforms to required interfaces.
var (
	_ caddy.Provisioner     = (*Provider)(nil)
	_ certmagic.DNSProvider = (*Provider)(nil)
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.enzonix",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision sets up the provider.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)
	p.APIKey = caddy.NewReplacer().ReplaceAll(p.APIKey, "")

	if p.APIKey == "" {
		return errors.New("enzonix: api_key is required")
	}

	if p.Timeout <= 0 {
		p.Timeout = caddy.Duration(defaultTimeout)
	}

	httpClient := &http.Client{
		Timeout: time.Duration(p.Timeout),
	}

	var opts []sdk.Option
	opts = append(opts, sdk.WithHTTPClient(httpClient))
	if strings.TrimSpace(p.APIEndpoint) != "" {
		opts = append(opts, sdk.WithBaseURL(p.APIEndpoint))
	}

	client, err := sdk.NewClient(p.APIKey, opts...)
	if err != nil {
		return fmt.Errorf("enzonix: create sdk client: %w", err)
	}

	p.client = client
	return nil
}

// Validate ensures the configuration is valid.
func (p *Provider) Validate() error {
	if p.APIKey == "" {
		return errors.New("enzonix: api_key is required")
	}
	if p.client == nil {
		return errors.New("enzonix: client not initialized")
	}
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile tokens.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.APIKey = d.Val()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "api_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.APIKey = d.Val()
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.APIEndpoint = d.Val()
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid duration for timeout: %v", err)
				}
				p.Timeout = caddy.Duration(dur)
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}

	return nil
}

// AppendRecords adds records to the zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return []libdns.Record{}, nil
	}

	result := make([]libdns.Record, 0, len(recs))
	for _, record := range recs {
		req := recordToCreateRequest(record)
		created, err := p.client.CreateRecord(ctx, zone, req)
		if err != nil {
			return nil, err
		}
		result = append(result, sdkRecordToLibdns(zone, *created))
	}

	return result, nil
}

// DeleteRecords removes records from the zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return []libdns.Record{}, nil
	}

	var existing []sdk.Record
	var err error

	resolved := make([]libdns.Record, 0, len(recs))
	for _, record := range recs {
		id := strings.TrimSpace(record.ID)
		if id == "" {
			if existing == nil {
				if existing, err = p.client.ListRecords(ctx, zone, nil); err != nil {
					return nil, err
				}
			}
			id = matchRecordID(existing, zone, record)
			if id == "" {
				continue
			}
		}

		if err := p.client.DeleteRecord(ctx, zone, id); err != nil {
			return nil, err
		}
		record.ID = id
		resolved = append(resolved, record)
	}

	return resolved, nil
}

// GetRecords retrieves records for the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	records, err := p.client.ListRecords(ctx, zone, nil)
	if err != nil {
		return nil, err
	}

	result := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		result = append(result, sdkRecordToLibdns(zone, rec))
	}
	return result, nil
}

// SetRecords replaces the existing zone records with the provided set.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return []libdns.Record{}, nil
	}

	result := make([]libdns.Record, 0, len(recs))
	for _, record := range recs {
		if strings.TrimSpace(record.ID) == "" {
			req := recordToCreateRequest(record)
			created, err := p.client.CreateRecord(ctx, zone, req)
			if err != nil {
				return nil, err
			}
			result = append(result, sdkRecordToLibdns(zone, *created))
			continue
		}

		updateReq := recordToUpdateRequest(record)
		updated, err := p.client.UpdateRecord(ctx, zone, record.ID, updateReq)
		if err != nil {
			return nil, err
		}
		result = append(result, sdkRecordToLibdns(zone, *updated))
	}

	return result, nil
}

func recordToCreateRequest(record libdns.Record) sdk.CreateRecordRequest {
	req := sdk.CreateRecordRequest{
		Name:    record.Name,
		Type:    record.Type,
		Content: record.Value,
	}

	if ttl := int(record.TTL / time.Second); ttl > 0 {
		req.TTL = ttl
	}
	if record.Priority > 0 {
		req.Priority = record.Priority
	}
	if record.Weight > 0 {
		req.Weight = record.Weight
	}

	return req
}

func recordToUpdateRequest(record libdns.Record) sdk.UpdateRecordRequest {
	req := sdk.UpdateRecordRequest{}

	if record.Name != "" {
		name := record.Name
		req.Name = &name
	}
	if record.Type != "" {
		typ := record.Type
		req.Type = &typ
	}
	if record.Value != "" {
		content := record.Value
		req.Content = &content
	}
	if ttl := int(record.TTL / time.Second); ttl > 0 {
		req.TTL = &ttl
	}
	if record.Priority > 0 {
		priority := record.Priority
		req.Priority = &priority
	}
	if record.Weight > 0 {
		weight := record.Weight
		req.Weight = &weight
	}

	return req
}

func sdkRecordToLibdns(zone string, record sdk.Record) libdns.Record {
	ttl := time.Duration(record.TTL) * time.Second
	return libdns.Record{
		ID:       record.ID,
		Type:     record.Type,
		Name:     libdns.RelativeName(strings.TrimSuffix(record.Name, "."), ensureTrailingDot(zone)),
		Value:    record.Content,
		TTL:      ttl,
		Priority: record.Priority,
		Weight:   record.Weight,
	}
}

func matchRecordID(records []sdk.Record, zone string, target libdns.Record) string {
	targetName := strings.TrimSuffix(libdns.AbsoluteName(target.Name, ensureTrailingDot(zone)), ".")
	for _, r := range records {
		name := strings.TrimSuffix(r.Name, ".")
		if strings.EqualFold(name, strings.TrimSuffix(targetName, ".")) &&
			strings.EqualFold(r.Type, target.Type) &&
			r.Content == target.Value {
			return r.ID
		}
	}
	return ""
}

func ensureTrailingDot(zone string) string {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return zone
	}
	if !strings.HasSuffix(zone, ".") {
		return zone + "."
	}
	return zone
}

package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"homelab-horizon/internal/config"
)

const cloudflareAPIBase = "https://api.cloudflare.com/client/v4"
const cloudflareTimeout = 30 * time.Second

// CloudflareProvider implements DNS operations using Cloudflare API
type CloudflareProvider struct {
	apiToken string
	zoneID   string // Optional: limit operations to specific zone
	client   *http.Client
}

// NewCloudflareProvider creates a new Cloudflare DNS provider
func NewCloudflareProvider(cfg *config.DNSProviderConfig) (*CloudflareProvider, error) {
	if cfg.CloudflareAPIToken == "" {
		return nil, fmt.Errorf("cloudflare requires api_token")
	}
	return &CloudflareProvider{
		apiToken: cfg.CloudflareAPIToken,
		zoneID:   cfg.CloudflareZoneID,
		client:   &http.Client{Timeout: cloudflareTimeout},
	}, nil
}

// Name returns the provider identifier
func (p *CloudflareProvider) Name() string {
	return "cloudflare"
}

func (p *CloudflareProvider) log(action string) {
	fmt.Printf("[Cloudflare] %s\n", action)
}

// cloudflareResponse is the common response wrapper
type cloudflareResponse struct {
	Success  bool            `json:"success"`
	Errors   []cfError       `json:"errors"`
	Messages []string        `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (p *CloudflareProvider) doRequest(method, path string, body interface{}) (json.RawMessage, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, cloudflareAPIBase+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var cfResp cloudflareResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return nil, fmt.Errorf("API error: %s (code %d)", cfResp.Errors[0].Message, cfResp.Errors[0].Code)
		}
		return nil, fmt.Errorf("API error: unknown error")
	}

	return cfResp.Result, nil
}

// cfZone represents a Cloudflare zone
type cfZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Nameservers []string `json:"name_servers"`
}

// ListZones returns available zones from Cloudflare
func (p *CloudflareProvider) ListZones() ([]Zone, error) {
	p.log("Listing zones...")

	// If a specific zone ID is configured, just return that zone
	if p.zoneID != "" {
		result, err := p.doRequest("GET", "/zones/"+p.zoneID, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get zone: %w", err)
		}

		var zone cfZone
		if err := json.Unmarshal(result, &zone); err != nil {
			return nil, fmt.Errorf("failed to parse zone: %w", err)
		}

		return []Zone{{
			ID:          zone.ID,
			Name:        zone.Name,
			DNSManaged:  zone.Status == "active",
			Nameservers: zone.Nameservers,
		}}, nil
	}

	result, err := p.doRequest("GET", "/zones", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	var cfZones []cfZone
	if err := json.Unmarshal(result, &cfZones); err != nil {
		return nil, fmt.Errorf("failed to parse zones: %w", err)
	}

	var zones []Zone
	for _, z := range cfZones {
		zones = append(zones, Zone{
			ID:          z.ID,
			Name:        z.Name,
			DNSManaged:  z.Status == "active",
			Nameservers: z.Nameservers,
		})
	}

	return zones, nil
}

// cfRecord represents a Cloudflare DNS record
type cfRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied,omitempty"`
}

// GetRecord retrieves a DNS record from Cloudflare
func (p *CloudflareProvider) GetRecord(zoneID, name, recordType string) (*Record, error) {
	p.log(fmt.Sprintf("Getting %s (%s)...", name, recordType))

	// Ensure name doesn't have trailing dot
	name = strings.TrimSuffix(name, ".")

	// Query for matching records
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recordType, name)
	result, err := p.doRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get record: %w", err)
	}

	var records []cfRecord
	if err := json.Unmarshal(result, &records); err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	if len(records) == 0 {
		return nil, nil // Record not found
	}

	r := records[0]
	return &Record{
		Name:   r.Name,
		Type:   r.Type,
		Value:  r.Content,
		TTL:    r.TTL,
		ZoneID: zoneID,
	}, nil
}

// CreateRecord creates a new DNS record
func (p *CloudflareProvider) CreateRecord(zoneID string, record Record) error {
	p.log(fmt.Sprintf("Creating %s -> %s...", record.Name, record.Value))

	// Ensure name doesn't have trailing dot
	name := strings.TrimSuffix(record.Name, ".")

	ttl := record.TTL
	if ttl <= 0 {
		ttl = 300
	}

	body := cfRecord{
		Type:    record.Type,
		Name:    name,
		Content: record.Value,
		TTL:     ttl,
		Proxied: false, // DNS-only, no Cloudflare proxy
	}

	_, err := p.doRequest("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), body)
	if err != nil {
		p.log(fmt.Sprintf("Create %s FAILED: %v", record.Name, err))
		return fmt.Errorf("failed to create record: %w", err)
	}

	p.log(fmt.Sprintf("Create %s SUCCESS", record.Name))
	return nil
}

// UpdateRecord updates an existing DNS record
func (p *CloudflareProvider) UpdateRecord(zoneID string, record Record) error {
	p.log(fmt.Sprintf("Updating %s -> %s...", record.Name, record.Value))

	// Ensure name doesn't have trailing dot
	name := strings.TrimSuffix(record.Name, ".")

	// First, find the existing record ID
	recordID, err := p.findRecordID(zoneID, name, record.Type)
	if err != nil {
		return err
	}

	ttl := record.TTL
	if ttl <= 0 {
		ttl = 300
	}

	if recordID == "" {
		// Record doesn't exist, create it
		return p.CreateRecord(zoneID, record)
	}

	body := cfRecord{
		Type:    record.Type,
		Name:    name,
		Content: record.Value,
		TTL:     ttl,
		Proxied: false,
	}

	_, err = p.doRequest("PATCH", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), body)
	if err != nil {
		p.log(fmt.Sprintf("Update %s FAILED: %v", record.Name, err))
		return fmt.Errorf("failed to update record: %w", err)
	}

	p.log(fmt.Sprintf("Update %s SUCCESS", record.Name))
	return nil
}

// DeleteRecord deletes a DNS record
func (p *CloudflareProvider) DeleteRecord(zoneID, name, recordType string) error {
	p.log(fmt.Sprintf("Deleting %s...", name))

	// Ensure name doesn't have trailing dot
	name = strings.TrimSuffix(name, ".")

	recordID, err := p.findRecordID(zoneID, name, recordType)
	if err != nil {
		return err
	}

	if recordID == "" {
		return fmt.Errorf("record not found")
	}

	_, err = p.doRequest("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}

	p.log(fmt.Sprintf("Delete %s SUCCESS", name))
	return nil
}

// SyncRecord updates a record if the value has changed
func (p *CloudflareProvider) SyncRecord(zoneID string, record Record) (changed bool, err error) {
	currentRecord, err := p.GetRecord(zoneID, record.Name, record.Type)
	if err != nil {
		p.log(fmt.Sprintf("GetRecord error for %s: %v, will try to create", record.Name, err))
		return true, p.CreateRecord(zoneID, record)
	}

	if currentRecord == nil {
		// Record doesn't exist, create it
		return true, p.CreateRecord(zoneID, record)
	}

	if currentRecord.Value == record.Value {
		p.log(fmt.Sprintf("%s already set to %s", record.Name, record.Value))
		return false, nil
	}

	p.log(fmt.Sprintf("%s value mismatch: current=%q new=%q", record.Name, currentRecord.Value, record.Value))
	return true, p.UpdateRecord(zoneID, record)
}

// findRecordID finds the ID of a record by name and type
func (p *CloudflareProvider) findRecordID(zoneID, name, recordType string) (string, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recordType, name)
	result, err := p.doRequest("GET", path, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get records: %w", err)
	}

	var records []cfRecord
	if err := json.Unmarshal(result, &records); err != nil {
		return "", fmt.Errorf("failed to parse records: %w", err)
	}

	if len(records) == 0 {
		return "", nil // Not found
	}

	return records[0].ID, nil
}

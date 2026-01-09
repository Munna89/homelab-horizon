package acme

import (
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/namedotcom"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// DNSProviderType identifies the DNS provider for ACME challenges
type DNSProviderType string

const (
	DNSProviderRoute53    DNSProviderType = "route53"
	DNSProviderNamecom    DNSProviderType = "namecom"
	DNSProviderCloudflare DNSProviderType = "cloudflare"
)

// DNSProviderConfig holds provider-specific credentials for ACME challenges
type DNSProviderConfig struct {
	Type DNSProviderType

	// Route53
	AWSAccessKeyID     string
	AWSSecretAccessKey string
	AWSRegion          string
	AWSHostedZoneID    string
	AWSProfile         string

	// Name.com
	NamecomUsername string
	NamecomAPIToken string

	// Cloudflare
	CloudflareAPIToken string
	CloudflareZoneID   string
}

// CreateChallengeProvider creates a Lego DNS challenge provider from configuration
func CreateChallengeProvider(cfg *DNSProviderConfig) (challenge.Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("dns provider config is nil")
	}

	switch cfg.Type {
	case DNSProviderRoute53:
		return createRoute53Provider(cfg)
	case DNSProviderNamecom:
		return createNamecomProvider(cfg)
	case DNSProviderCloudflare:
		return createCloudflareProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown dns provider type for ACME: %s", cfg.Type)
	}
}

// createRoute53Provider creates a Lego Route53 provider
func createRoute53Provider(cfg *DNSProviderConfig) (challenge.Provider, error) {
	// Set environment variables for lego's route53 provider
	// The provider reads these during initialization
	if cfg.AWSAccessKeyID != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", cfg.AWSAccessKeyID)
	}
	if cfg.AWSSecretAccessKey != "" {
		os.Setenv("AWS_SECRET_ACCESS_KEY", cfg.AWSSecretAccessKey)
	}
	if cfg.AWSRegion != "" {
		os.Setenv("AWS_REGION", cfg.AWSRegion)
	}
	if cfg.AWSHostedZoneID != "" {
		os.Setenv("AWS_HOSTED_ZONE_ID", cfg.AWSHostedZoneID)
	}
	if cfg.AWSProfile != "" {
		os.Setenv("AWS_PROFILE", cfg.AWSProfile)
	}

	provider, err := route53.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create route53 provider: %w", err)
	}

	return provider, nil
}

// createNamecomProvider creates a Lego Name.com provider
func createNamecomProvider(cfg *DNSProviderConfig) (challenge.Provider, error) {
	// Set environment variables for lego's namedotcom provider
	if cfg.NamecomUsername != "" {
		os.Setenv("NAMECOM_USERNAME", cfg.NamecomUsername)
	}
	if cfg.NamecomAPIToken != "" {
		os.Setenv("NAMECOM_API_TOKEN", cfg.NamecomAPIToken)
	}

	provider, err := namedotcom.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create namecom provider: %w", err)
	}

	return provider, nil
}

// createCloudflareProvider creates a Lego Cloudflare provider
func createCloudflareProvider(cfg *DNSProviderConfig) (challenge.Provider, error) {
	// Set environment variables for lego's cloudflare provider
	if cfg.CloudflareAPIToken != "" {
		os.Setenv("CF_DNS_API_TOKEN", cfg.CloudflareAPIToken)
	}
	if cfg.CloudflareZoneID != "" {
		os.Setenv("CF_ZONE_API_TOKEN", cfg.CloudflareAPIToken) // Same token for zone API
	}

	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare provider: %w", err)
	}

	return provider, nil
}

// ProviderName returns the name of the provider for a given config
func ProviderName(cfg *DNSProviderConfig) string {
	if cfg == nil {
		return "unknown"
	}
	return string(cfg.Type)
}

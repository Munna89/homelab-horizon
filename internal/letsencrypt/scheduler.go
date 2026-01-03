package letsencrypt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RenewalResult represents the result of a renewal attempt
type RenewalResult struct {
	Domain    string
	Success   bool
	Message   string
	Timestamp time.Time
}

// SchedulerConfig holds configuration for the renewal scheduler
type SchedulerConfig struct {
	CheckInterval   time.Duration // How often to check for renewals (default: 24h)
	RenewalWindow   time.Duration // Renew if expiry is within this window (default: 30 days)
	OnRenewal       func(result RenewalResult)
	OnHAProxyReload func(err error)
}

// Scheduler handles automatic certificate renewal
type Scheduler struct {
	manager *Manager
	config  SchedulerConfig
	stopCh  chan struct{}
	results []RenewalResult
	mu      sync.RWMutex
}

// NewScheduler creates a new renewal scheduler
func NewScheduler(manager *Manager, cfg SchedulerConfig) *Scheduler {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 24 * time.Hour
	}
	if cfg.RenewalWindow == 0 {
		cfg.RenewalWindow = 30 * 24 * time.Hour // 30 days
	}

	return &Scheduler{
		manager: manager,
		config:  cfg,
		stopCh:  make(chan struct{}),
	}
}

// Start begins the background renewal scheduler
func (s *Scheduler) Start() {
	go s.run()
}

// Stop halts the scheduler
func (s *Scheduler) Stop() {
	close(s.stopCh)
}

// GetResults returns recent renewal results
func (s *Scheduler) GetResults() []RenewalResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]RenewalResult, len(s.results))
	copy(results, s.results)
	return results
}

func (s *Scheduler) run() {
	// Check immediately on start
	s.checkAndRenew()

	ticker := time.NewTicker(s.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndRenew()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Scheduler) checkAndRenew() {
	var renewed bool

	for _, d := range s.manager.config.Domains {
		needsRenewal, reason := s.needsRenewal(d)
		if !needsRenewal {
			continue
		}

		result := RenewalResult{
			Domain:    d.Domain,
			Timestamp: time.Now(),
		}

		// Attempt renewal
		err := s.manager.RequestCertForDomain(d)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("Renewal failed: %v", err)
		} else {
			result.Success = true
			result.Message = fmt.Sprintf("Renewed successfully (%s)", reason)
			renewed = true
		}

		s.addResult(result)

		if s.config.OnRenewal != nil {
			s.config.OnRenewal(result)
		}
	}

	// Reload HAProxy if any certs were renewed
	if renewed {
		err := s.reloadHAProxy()
		if s.config.OnHAProxyReload != nil {
			s.config.OnHAProxyReload(err)
		}
	}
}

func (s *Scheduler) needsRenewal(d DomainConfig) (bool, string) {
	baseDomain := strings.TrimPrefix(d.Domain, "*.")
	certPath := filepath.Join(s.manager.config.CertDir, "live", baseDomain, "fullchain.pem")

	// Check if cert exists
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, "certificate does not exist"
		}
		return false, "" // Can't read, skip
	}

	// Parse certificate to check expiry
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, "invalid certificate PEM"
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, "invalid certificate"
	}

	// Check if within renewal window
	timeUntilExpiry := time.Until(cert.NotAfter)
	if timeUntilExpiry <= s.config.RenewalWindow {
		return true, fmt.Sprintf("expires in %d days", int(timeUntilExpiry.Hours()/24))
	}

	// Check if SANs are missing (sub-zone added after initial cert)
	hasCert, missingSANs, _ := s.manager.CheckCertSANs(d)
	if hasCert && len(missingSANs) > 0 {
		return true, fmt.Sprintf("missing SANs: %v", missingSANs)
	}

	return false, ""
}

func (s *Scheduler) addResult(result RenewalResult) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Keep last 50 results
	s.results = append(s.results, result)
	if len(s.results) > 50 {
		s.results = s.results[len(s.results)-50:]
	}
}

func (s *Scheduler) reloadHAProxy() error {
	// First, package all certs for HAProxy
	if err := s.manager.PackageAllForHAProxy(); err != nil {
		return fmt.Errorf("packaging certs: %w", err)
	}

	// Check if haproxy is running via systemctl
	checkCmd := exec.Command("systemctl", "is-active", "--quiet", "haproxy")
	if err := checkCmd.Run(); err != nil {
		// HAProxy not running, nothing to reload
		return nil
	}

	// Reload haproxy
	reloadCmd := exec.Command("systemctl", "reload", "haproxy")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("reloading haproxy: %w", err)
	}

	return nil
}

// CheckNow triggers an immediate renewal check
func (s *Scheduler) CheckNow() []RenewalResult {
	var results []RenewalResult
	var renewed bool

	for _, d := range s.manager.config.Domains {
		needsRenewal, reason := s.needsRenewal(d)

		result := RenewalResult{
			Domain:    d.Domain,
			Timestamp: time.Now(),
		}

		if !needsRenewal {
			result.Success = true
			result.Message = "Certificate is valid, no renewal needed"
			results = append(results, result)
			continue
		}

		// Attempt renewal
		err := s.manager.RequestCertForDomain(d)
		if err != nil {
			result.Success = false
			result.Message = fmt.Sprintf("Renewal failed: %v", err)
		} else {
			result.Success = true
			result.Message = fmt.Sprintf("Renewed successfully (%s)", reason)
			renewed = true
		}

		results = append(results, result)
		s.addResult(result)

		if s.config.OnRenewal != nil {
			s.config.OnRenewal(result)
		}
	}

	// Reload HAProxy if any certs were renewed
	if renewed {
		err := s.reloadHAProxy()
		if s.config.OnHAProxyReload != nil {
			s.config.OnHAProxyReload(err)
		}
	}

	return results
}

// GetCertExpiry returns expiry info for all configured domains
func (s *Scheduler) GetCertExpiry() []CertExpiryInfo {
	var infos []CertExpiryInfo

	for _, d := range s.manager.config.Domains {
		info := CertExpiryInfo{
			Domain: d.Domain,
		}

		baseDomain := strings.TrimPrefix(d.Domain, "*.")
		certPath := filepath.Join(s.manager.config.CertDir, "live", baseDomain, "fullchain.pem")

		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			info.Error = "Certificate not found"
			infos = append(infos, info)
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			info.Error = "Invalid PEM"
			infos = append(infos, info)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			info.Error = "Invalid certificate"
			infos = append(infos, info)
			continue
		}

		info.NotAfter = cert.NotAfter
		info.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
		info.NeedsRenewal = time.Until(cert.NotAfter) <= s.config.RenewalWindow

		infos = append(infos, info)
	}

	return infos
}

// CertExpiryInfo holds certificate expiry information
type CertExpiryInfo struct {
	Domain        string
	NotAfter      time.Time
	DaysRemaining int
	NeedsRenewal  bool
	Error         string
}

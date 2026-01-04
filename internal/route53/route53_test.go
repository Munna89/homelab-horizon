package route53

import (
	"testing"
)

func TestCheckIPv6(t *testing.T) {
	status := CheckIPv6()

	t.Logf("HasAddress: %v", status.HasAddress)
	t.Logf("HasGlobalIP: %v", status.HasGlobalIP)
	t.Logf("Connectivity: %v", status.Connectivity)
	t.Logf("PublicIPv6: %s", status.PublicIPv6)
	t.Logf("Error: %s", status.Error)
	t.Logf("Recommendation: %s", status.Recommendation)

	if status.Connectivity && status.PublicIPv6 == "" {
		t.Error("Connectivity true but no PublicIPv6")
	}

	if !status.HasAddress && status.HasGlobalIP {
		t.Error("HasGlobalIP true but HasAddress false")
	}
}

func TestGetPublicIP(t *testing.T) {
	ip, err := GetPublicIP()
	if err != nil {
		t.Skipf("Could not get public IP (may be offline): %v", err)
	}

	if ip == "" {
		t.Error("GetPublicIP returned empty string")
	}

	t.Logf("Public IP: %s", ip)
}

package qr

import (
	"strings"
	"testing"
)

func TestNotAvailableSVG_ValidSVGStructure(t *testing.T) {
	svg := notAvailableSVG(200)

	if !strings.HasPrefix(svg, "<svg") {
		t.Error("should start with <svg tag")
	}
	if !strings.HasSuffix(strings.TrimSpace(svg), "</svg>") {
		t.Error("should end with </svg> tag")
	}
	if !strings.Contains(svg, "xmlns") {
		t.Error("should contain xmlns attribute")
	}
}

func TestNotAvailableSVG_ContainsExpectedContent(t *testing.T) {
	svg := notAvailableSVG(200)

	expectedContent := []string{
		"QR code unavailable",
		"apt install qrencode",
	}

	for _, expected := range expectedContent {
		if !strings.Contains(svg, expected) {
			t.Errorf("should contain %q", expected)
		}
	}
}

func TestNotAvailableSVG_SizeParameter(t *testing.T) {
	sizes := []int{100, 200, 300, 400}

	for _, size := range sizes {
		svg := notAvailableSVG(size)
		if !strings.HasPrefix(svg, "<svg") {
			t.Errorf("size %d: should produce valid SVG", size)
		}
	}
}

func TestGenerateSVG_FallbackWhenUnavailable(t *testing.T) {
	if !Available() {
		svg := GenerateSVG("test data", 200)
		if !strings.Contains(svg, "QR code unavailable") {
			t.Error("should return placeholder when qrencode not available")
		}
	}
}

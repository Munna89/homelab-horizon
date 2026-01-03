package qr

import (
	"bytes"
	"os/exec"
)

// GenerateSVG generates an SVG QR code using qrencode
// Returns a placeholder SVG with install instructions if qrencode is not available
func GenerateSVG(data string, size int) string {
	if !Available() {
		return notAvailableSVG(size)
	}

	cmd := exec.Command("qrencode", "-t", "SVG", "-o", "-", "-s", "8", "-m", "2")
	cmd.Stdin = bytes.NewBufferString(data)

	output, err := cmd.Output()
	if err != nil {
		return notAvailableSVG(size)
	}

	return string(output)
}

// Available checks if qrencode is installed
func Available() bool {
	_, err := exec.LookPath("qrencode")
	return err == nil
}

// notAvailableSVG returns a placeholder SVG with install instructions
func notAvailableSVG(size int) string {
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="200" height="200">
  <rect width="200" height="200" fill="#f0f0f0" stroke="#ccc"/>
  <text x="100" y="80" text-anchor="middle" font-family="sans-serif" font-size="14" fill="#666">QR code unavailable</text>
  <text x="100" y="110" text-anchor="middle" font-family="monospace" font-size="11" fill="#333">apt install qrencode</text>
  <text x="100" y="140" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#666">to enable QR codes</text>
</svg>`
}

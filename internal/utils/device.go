package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/medama-io/go-useragent"
)

// GenerateDeviceFingerprint creates a unique device identifier from request headers
func GenerateDeviceFingerprint(userAgent, ipAddress, acceptLanguage, acceptEncoding string) (string, error) {
	host, _, err := net.SplitHostPort(ipAddress)
	if err != nil {
		return "", err
	}
	data := fmt.Sprintf("%s|%s|%s|%s",
		userAgent,
		host,
		acceptLanguage,
		acceptEncoding,
	)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:16]), nil
}

// ParseDeviceName extracts readable device information from the user agent
func ParseDeviceName(userAgentString string) string {
	parser := useragent.NewParser()
	ua := parser.Parse(userAgentString)

	deviceType := "Unknown"
	if ua.IsDesktop() {
		deviceType = "Desktop"
	} else if ua.IsMobile() {
		deviceType = "Mobile"
	} else if ua.IsTablet() {
		deviceType = "Tablet"
	} else if ua.IsBot() {
		deviceType = "Bot"
	}

	browser := ua.Browser()
	os := ua.OS()

	if browser != "" && os != "" {
		return fmt.Sprintf("%s on %s (%s)", browser, os, deviceType)
	} else if browser != "" {
		return fmt.Sprintf("%s (%s)", browser, deviceType)
	} else if os != "" {
		return fmt.Sprintf("%s (%s)", os, deviceType)
	}

	return deviceType
}

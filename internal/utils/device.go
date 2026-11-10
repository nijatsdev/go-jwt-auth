package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/medama-io/go-useragent"
)

var (
	deviceParser     *useragent.Parser
	deviceParserOnce sync.Once
)

func deviceUAParser() *useragent.Parser {
	deviceParserOnce.Do(func() {
		deviceParser = useragent.NewParser()
	})
	return deviceParser
}

// GenerateDeviceFingerprint creates a stable device identifier from client-controlled headers.
// IP is intentionally excluded (spoofable behind proxies, brittle on mobile networks).
func GenerateDeviceFingerprint(userAgent, acceptLanguage, acceptEncoding string) string {
	data := fmt.Sprintf("%s|%s|%s", userAgent, acceptLanguage, acceptEncoding)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:16])
}

// ParseDeviceName extracts readable device information from the user agent
func ParseDeviceName(userAgentString string) string {
	ua := deviceUAParser().Parse(userAgentString)

	deviceType := "Unknown"
	if ua.IsDesktop() {
		deviceType = "Desktop"
	} else if ua.IsTablet() {
		deviceType = "Tablet"
	} else if ua.IsMobile() {
		deviceType = "Mobile"
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

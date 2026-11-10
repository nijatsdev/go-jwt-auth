package utils

import "net"

// HostFromAddr returns the host part of a RemoteAddr-style value (with or without port).
func HostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

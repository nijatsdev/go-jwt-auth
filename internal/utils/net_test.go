package utils

import "testing"

func TestHostFromAddr(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:12345", "192.168.1.1"},
		{"203.0.113.5", "203.0.113.5"},
		{"[::1]:8080", "::1"},
	}
	for _, tc := range tests {
		if got := HostFromAddr(tc.addr); got != tc.want {
			t.Errorf("HostFromAddr(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

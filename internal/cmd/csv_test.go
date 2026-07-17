package cmd

import (
	"reflect"
	"testing"
)

func TestExtractDomainsFromCSV(t *testing.T) {
	tests := []struct {
		name    string
		records [][]string
		want    []string
	}{
		{
			name: "old format (CERT_DOMAIN at index 2)",
			records: [][]string{
				{"IP", "ORIGIN", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"},
				{"103.103.245.124", "103.103.245.124", "cwangrz.top", "Let's Encrypt", "HK"},
				{"103.103.245.129", "103.103.245.129", "*.bozai.cc", "ZeroSSL", "HK"}, // should be excluded due to wildcard
				{"103.103.245.58", "103.103.245.58", "cloudflare.net", "Let's Encrypt", "HK"},
				{"103.103.245.124", "103.103.245.124", "cwangrz.top", "Let's Encrypt", "HK"}, // duplicate
			},
			want: []string{"cwangrz.top", "cloudflare.net"},
		},
		{
			name: "new format (CERT_DOMAIN at index 8)",
			records: [][]string{
				{"IP", "ORIGIN", "TLS", "ALPN", "CURVE", "CERT_LENGTH", "CERT_SIGNATURE", "CERT_PUBLICKEY", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"},
				{"5.45.102.238", "5.45.102.238", "TLS 1.3", "h2", "X25519", "2793", "SHA256-RSA", "RSA", "wantedlink.de", "Let's Encrypt", "DE"},
				{"5.45.102.201", "5.45.102.201", "TLS 1.3", "h2", "X25519", "5443", "SHA256-RSA", "RSA", "mail.mpache.com", "Let's Encrypt", "DE"},
				{"5.45.102.202", "5.45.102.202", "TLS 1.3", "h2", "X25519", "4045", "SHA256-RSA", "RSA", "pge.ring0.de", "Let's Encrypt", "DE"},
			},
			want: []string{"wantedlink.de", "mail.mpache.com", "pge.ring0.de"},
		},
		{
			name: "no CERT_DOMAIN in header, fallback to index 2",
			records: [][]string{
				{"IP", "ORIGIN", "SOMETHING", "CERT_ISSUER", "GEO_CODE"},
				{"1.1.1.1", "1.1.1.1", "fallback.com", "Let's Encrypt", "US"},
			},
			want: []string{"fallback.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainsFromCSV(tt.records)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractDomainsFromCSV() = %v, want %v", got, tt.want)
			}
		})
	}
}

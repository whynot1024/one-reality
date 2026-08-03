package scanner

import (
	"net"
)

type HostType int

const (
	HostTypeIP HostType = iota + 1
	HostTypeCIDR
	HostTypeDomain
)

type Host struct {
	IP     net.IP
	Origin string
	Type   HostType
}

type ScanResult struct {
	IP            string
	Origin        string
	TLSVersion    string
	ALPN          string
	Curve         string
	CertLength    string
	CertSignature string
	CertPublicKey string
	CertDomain    string
	CertIssuer    string
	GeoCode       string
}

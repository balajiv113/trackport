package trackapi

import (
	"context"
	"net"
)

type (
	Protocol = uint16
	Action   = uint16

	Tracker = string
)

const (
	TCP Protocol = iota
	UDP
)

const (
	OPEN Action = iota
	CLOSE
)

const (
	EBPF  = "EBPF"
	AUDIT = "AUDIT"
)

func ProtocolToString(protocol Protocol) string {
	switch protocol {
	case UDP:
		return "udp"
	default:
		return "tcp"
	}
}

type PortEvent struct {
	Protocol Protocol
	Action   Action
	Ip       net.IP
	Port     string
}

type PortTracker interface {
	Run(ctx context.Context) error
}

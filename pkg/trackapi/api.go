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

type PortEvent struct {
	Protocol Protocol
	Action   Action
	IP       net.IP
	Port     string
}

type PortTracker interface {
	Run(ctx context.Context) error
}

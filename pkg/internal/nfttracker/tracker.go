package nfttracker

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sirupsen/logrus"
)

type NftPortTracker struct {
	CallbackFn func(event *trackapi.PortEvent)
}

func NewTracker(callbackFn func(event *trackapi.PortEvent)) trackapi.PortTracker {
	return &NftPortTracker{CallbackFn: callbackFn}
}

func (m *NftPortTracker) Run(ctx context.Context) error {
	conn, err := nftables.New()
	if err != nil {
		logrus.Error("error in creating nftable", err)
	}
	monitor := nftables.NewMonitor()

	events, err := conn.AddMonitor(monitor)
	if err != nil {
		logrus.Error("error in nftables add monitor", err)
	}
	for event := range events {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if event.Type == nftables.MonitorEventTypeNewRule || event.Type == nftables.MonitorEventTypeDelRule {
			rule := event.Data.(*nftables.Rule)
			if isDNATRule(rule) {
				portEvent := m.convertToEvent(rule)
				if portEvent != nil {
					if event.Type == nftables.MonitorEventTypeDelRule {
						portEvent.Action = trackapi.CLOSE
					}
					m.CallbackFn(portEvent)
				}
			}
		}
	}
	return nil
}

func (m *NftPortTracker) convertToEvent(dnatRule *nftables.Rule) *trackapi.PortEvent {
	protocol := -1
	port := -1
	offset := -1
	var address net.IP
	for _, e := range dnatRule.Exprs {
		switch t := e.(type) {
		case *expr.Payload:
			offset = int(t.Offset)
		case *expr.Cmp:
			if offset == 16 && len(t.Data) == 4 { // TODO support ipv6
				address = t.Data
			}
			if offset == 9 {
				protocol = int(extractProtocolFromCmp(t))
			}
			if offset == 2 {
				port = extractPortFromCmp(t)
			}
		}
	}
	if protocol != -1 && port != -1 {
		if address == nil {
			address = net.ParseIP("0.0.0.0")
		}
		return &trackapi.PortEvent{
			Protocol: trackapi.Protocol(protocol),
			Action:   trackapi.OPEN,
			IP:       address,
			Port:     strconv.Itoa(port),
		}
	}

	// No port found
	return nil
}

// isDNATRule filters DNAT rules by checking their type and expressions.
func isDNATRule(rule *nftables.Rule) bool {
	if !isNat(rule) {
		return false
	}

	for _, exp := range rule.Exprs {
		if target, ok := exp.(*expr.Target); ok {
			return target.Name == "DNAT"
		}
	}
	return false
}

func isNat(rule *nftables.Rule) bool {
	if rule == nil || rule.Table == nil || rule.Chain == nil {
		return false
	}

	if rule.Table.Name != "nat" {
		return false
	}
	return true
}

func extractProtocolFromCmp(cmpExpr *expr.Cmp) trackapi.Protocol {
	if cmpExpr.Data[0] == 17 {
		return trackapi.UDP
	}
	return trackapi.TCP
}

func extractPortFromCmp(cmpExpr *expr.Cmp) int {
	port := binary.BigEndian.Uint16(cmpExpr.Data)
	return int(port)
}

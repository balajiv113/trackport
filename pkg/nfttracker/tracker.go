package nfttracker

import (
	"context"
	"encoding/binary"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
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
				if err != nil {
					logrus.Error("error in nftables events", err)
				}
				portEvent := extractPortEvent(rule)
				if event.Type == nftables.MonitorEventTypeDelRule {
					portEvent.Action = trackapi.CLOSE
				}
				m.CallbackFn(portEvent)
			}
		}
	}
	return nil
}

// isDNATRule filters DNAT rules by checking their type and expressions
func isDNATRule(rule *nftables.Rule) bool {
	if rule == nil || rule.Table == nil || rule.Chain == nil {
		return false
	}

	if rule.Table.Name != "nat" {
		return false
	}

	for _, exp := range rule.Exprs {
		if target, ok := exp.(*expr.Target); ok {
			return target.Name == "DNAT"
		}
	}
	return false
}

func extractPortEvent(rule *nftables.Rule) *trackapi.PortEvent {
	protocol := -1
	port := -1
	for _, e := range rule.Exprs {
		switch t := e.(type) {
		case *expr.Cmp:
			if protocol == -1 {
				protocol = int(extractProtocolFromCmp(t))
			} else {
				port = int(extractPortFromCmp(t))
			}
		}
	}
	if protocol != -1 && port != -1 {
		return &trackapi.PortEvent{
			Protocol: trackapi.Protocol(protocol),
			Action:   trackapi.OPEN,
			Ip:       net.ParseIP("0.0.0.0"), //TODO support interface level binding using saddr
			Port:     strconv.Itoa(port),
		}
	}

	// No port found
	return nil
}

func extractProtocolFromCmp(cmpExpr *expr.Cmp) trackapi.Protocol {
	if len(cmpExpr.Data) == 1 {
		if cmpExpr.Data[0] == 17 {
			return trackapi.UDP
		}
	}
	return trackapi.TCP
}

func extractPortFromCmp(cmpExpr *expr.Cmp) uint16 {
	if len(cmpExpr.Data) == 2 {
		port := binary.BigEndian.Uint16(cmpExpr.Data)
		return port
	}
	return 0
}

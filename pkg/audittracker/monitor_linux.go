package audittracker

import (
	"context"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
	"time"
)

type AuditPortTracker struct {
	trackapi.PortTracker
	callbackFn func(event *trackapi.PortEvent)

	ports map[string]*trackapi.PortEvent
}

func NewTracker(callbackFn func(event *trackapi.PortEvent)) trackapi.PortTracker {
	return &AuditPortTracker{callbackFn: callbackFn, ports: make(map[string]*trackapi.PortEvent)}
}

func (p *AuditPortTracker) Run(ctx context.Context) error {
	client, err := libaudit.NewMulticastAuditClient(nil)
	if err != nil {
		logrus.Errorf("Failed to create audit client: %v", err)
	}
	defer client.Close()

	if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
		logrus.Errorf("Failed to enable audit event: %v", err)
	}

	_, err = client.DeleteRules()
	if err != nil {
		return err
	}
	syscallRule := &rule.SyscallRule{
		Type:     rule.PrependSyscallRuleType,
		List:     "exit",
		Action:   "always",
		Syscalls: []string{"socket", "getsockname", "kill", "tgkill", "tkill"},
	}
	build, err := rule.Build(syscallRule)
	if err := client.AddRule(build); err != nil && err.Error() != "rule exists" {
		logrus.Errorf("Failed to add audit rule: %v", err)
		return nil
	}
	logrus.Println("Audit rule added successfully to monitor bind() syscalls")

	events := make(chan *aucoalesce.Event)

	reassembler, err := libaudit.NewReassembler(100, 500*time.Millisecond, &streamHandler{event: events})
	go func() {
		for {
			select {
			case <-ctx.Done():
				break
			default:
				rawEvent, err := client.Receive(false)
				if err != nil {
					logrus.Errorf("Failed to receive audit event: %v", err)
				}
				if rawEvent != nil {
					err = reassembler.Push(rawEvent.Type, rawEvent.Data)
					if err != nil {
						logrus.Errorf("Failed to receive audit event: %v", err)
					}
				}
			}
		}
	}()

	for event := range events {
		if ctx.Err() != nil {
			return nil
		}

		if event.Data["syscall"] == "socket" {
			socketType := event.Data["a1"]
			callEvent := &trackapi.PortEvent{}
			callEvent.Action = trackapi.OPEN
			if socketType == "1" {
				callEvent.Protocol = trackapi.TCP
			} else if socketType == "2" {
				callEvent.Protocol = trackapi.UDP
			}
			p.ports[event.Process.PID] = callEvent
		} else if event.Data["syscall"] == "getsockname" {
			callEvent, ok := p.ports[event.Process.PID]
			if ok {
				callEvent.Ip = net.ParseIP(event.Data["socket_addr"])
				callEvent.Port = event.Data["socket_port"]
				callEvent.Action = trackapi.OPEN
				callEvent.Port = event.Data["socket_port"]
				p.callbackFn(callEvent)
			}
		} else if strings.Contains(event.Data["syscall"], "kill") {
			callEvent, ok := p.ports[event.Process.PID]
			if ok {
				callEvent.Action = trackapi.CLOSE
				if callEvent.Ip != nil {
					p.callbackFn(callEvent)
				}
				delete(p.ports, event.Process.PID)
			}
		}
	}
	return nil
}

type streamHandler struct {
	event chan *aucoalesce.Event
}

func (s *streamHandler) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	if err := s.outputMultipleMessages(msgs); err != nil {
		logrus.Printf("[WARN] failed writing message to output: %v", err)
	}
}

func (*streamHandler) EventsLost(count int) {
	logrus.Printf("detected the loss of %v sequences.", count)
}

func (s *streamHandler) outputMultipleMessages(msgs []*auparse.AuditMessage) error {
	event, err := aucoalesce.CoalesceMessages(msgs)
	if err != nil {
		logrus.Printf("failed to coalesce messages: %v", err)
		return nil
	}
	s.event <- event
	return nil
}

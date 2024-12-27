package bpftracker

import (
	"context"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	tracker := &EbpfPortTracker{callbackFn: func(event *trackapi.PortEvent) {
		if event.Port == "8081" {
			assert.Equal(t, event.Protocol, trackapi.TCP)
			assert.Equal(t, event.Ip.String(), "127.0.0.1")
			assert.Equal(t, event.Action, trackapi.OPEN)
			net.Dial("tcp", "127.0.0.1:8081")
		}
	}}

	go tracker.Run(context.Background())
	listen, _ := net.Listen("tcp", "127.0.0.1:8081")
	time.Sleep(5 * time.Second)
	listen.Accept()
}

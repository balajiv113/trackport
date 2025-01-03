package bpftracker

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/stretchr/testify/assert"
)

func TestTCP(t *testing.T) {
	events := make(chan *trackapi.PortEvent)
	tracker := NewTracker(func(event *trackapi.PortEvent) {
		events <- event
	})

	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		_ = tracker.Run(ctx)
	}()
	time.Sleep(2 * time.Second)

	t.Run("test TCP4 listen loopback", func(t *testing.T) {
		ListenAndVerify(t, events, "tcp", "127.0.0.1:8081", "127.0.0.1", "8081")
	})

	t.Run("test TCP4 listen all interface", func(t *testing.T) {
		ListenAndVerify(t, events, "tcp4", "0.0.0.0:8081", "0.0.0.0", "8081")
	})

	t.Run("test TCP6 listen loopback", func(t *testing.T) {
		ListenAndVerify(t, events, "tcp", "[::1]:8081", "::1", "8081")
	})

	t.Run("test TCP6 listen all interface", func(t *testing.T) {
		ListenAndVerify(t, events, "tcp", "0.0.0.0:8081", "::", "8081")
	})

	t.Run("test random port", func(t *testing.T) {
		ListenAndVerify(t, events, "tcp", "0.0.0.0:", "::", "")
	})
	cancelFunc()
}

func TestUDP(t *testing.T) {
	events := make(chan *trackapi.PortEvent)
	tracker := NewTracker(func(event *trackapi.PortEvent) {
		events <- event
	})

	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		_ = tracker.Run(ctx)
	}()
	time.Sleep(2 * time.Second)

	t.Run("test UDP4 listen loopback", func(t *testing.T) {
		ListenAndVerify(t, events, "udp", "127.0.0.1:8081", "127.0.0.1", "8081")
	})

	t.Run("test UDP4 listen all interface", func(t *testing.T) {
		ListenAndVerify(t, events, "udp4", "0.0.0.0:8081", "0.0.0.0", "8081")
	})

	t.Run("test UDP6 listen loopback", func(t *testing.T) {
		ListenAndVerify(t, events, "udp", "[::1]:8081", "::1", "8081")
	})

	t.Run("test UDP6 listen all interface", func(t *testing.T) {
		ListenAndVerify(t, events, "udp", "0.0.0.0:8081", "::", "8081")
	})

	t.Run("test random port", func(t *testing.T) {
		ListenAndVerify(t, events, "udp", "0.0.0.0:", "::", "")
	})
	cancelFunc()
}

func ListenAndVerify(t *testing.T, events chan *trackapi.PortEvent, network, address, eAddress, ePort string) {
	protocol := trackapi.UDP
	if strings.HasPrefix(network, "tcp") {
		protocol = trackapi.TCP
	}

	var closer io.Closer
	if protocol == trackapi.TCP {
		listen, err := net.Listen(network, address)
		assert.Nil(t, err)
		go func() {
			_, _ = listen.Accept()
		}()
		closer = listen
	} else {
		udp, err := net.ListenPacket(network, address)
		assert.Nil(t, err)
		closer = udp
	}

	// verify event is received correctly
	event := <-events
	assert.Equal(t, protocol, event.Protocol)
	assert.Equal(t, eAddress, event.IP.String())
	assert.Equal(t, trackapi.OPEN, event.Action)
	if ePort != "" {
		assert.Equal(t, ePort, event.Port)
	} else {
		assert.NotEmpty(t, event.Port)
	}

	_ = closer.Close()
	event = <-events
	assert.Equal(t, protocol, event.Protocol)
	assert.Equal(t, eAddress, event.IP.String())
	assert.Equal(t, trackapi.CLOSE, event.Action)
	if ePort != "" {
		assert.Equal(t, ePort, event.Port)
	} else {
		assert.NotEmpty(t, event.Port)
	}
}

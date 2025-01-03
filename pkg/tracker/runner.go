package tracker

import (
	"context"
	"fmt"
	"sync"

	"github.com/balajiv113/trackport/pkg/internal/bpftracker"
	"github.com/balajiv113/trackport/pkg/internal/nfttracker"
	"github.com/balajiv113/trackport/pkg/trackapi"
)

type Runner struct {
	options []RunnerOption

	openPortsRw sync.Mutex
	openPorts   map[string]*trackapi.PortEvent
}

type EventCallback func(event *trackapi.PortEvent)

type RunnerOption func(EventCallback) trackapi.PortTracker

func WithBpf() RunnerOption {
	return func(callBack EventCallback) trackapi.PortTracker {
		return bpftracker.NewTracker(callBack)
	}
}

func WithNft() RunnerOption {
	return func(callBack EventCallback) trackapi.PortTracker {
		return nfttracker.NewTracker(callBack)
	}
}

func NewRunner(options ...RunnerOption) *Runner {
	openPorts := make(map[string]*trackapi.PortEvent)
	return &Runner{options: options, openPorts: openPorts}
}

func (r *Runner) cacheCallback(callBack func(event *trackapi.PortEvent)) func(event *trackapi.PortEvent) {
	return func(event *trackapi.PortEvent) {
		r.openPortsRw.Lock()
		defer r.openPortsRw.Unlock()
		key := key(event)
		if event.Action == trackapi.OPEN {
			if _, ok := r.openPorts[key]; ok {
				return
			}
			r.openPorts[key] = event
		} else if event.Action == trackapi.CLOSE {
			if _, ok := r.openPorts[key]; !ok {
				return
			}
			delete(r.openPorts, key)
		}
		callBack(event)
	}
}

func (r *Runner) Run(ctx context.Context, callBack func(event *trackapi.PortEvent)) error {
	errorCh := make(chan error)

	callback := r.cacheCallback(callBack)
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	for _, opt := range r.options {
		tracker := opt(callback)
		go func() {
			err := tracker.Run(cancelCtx)
			errorCh <- err
		}()
	}
	defer cancelFunc()
	return <-errorCh
}

func key(event *trackapi.PortEvent) string {
	return fmt.Sprintf("%d-%s-%s", event.Protocol, event.IP.String(), event.Port)
}

package tracker

import (
	"context"
	"fmt"
	"github.com/balajiv113/trackport/pkg/bpftracker"
	"github.com/balajiv113/trackport/pkg/nfttracker"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"sync"
)

type Runner struct {
	options []RunnerOption

	openPortsRw sync.Mutex
	openPorts   map[string]*trackapi.PortEvent
}

type RunnerOption func(func(event *trackapi.PortEvent)) trackapi.PortTracker

func WithBpf() RunnerOption {
	return func(callBack func(event *trackapi.PortEvent)) trackapi.PortTracker {
		return &bpftracker.EbpfPortTracker{CallbackFn: callBack}
	}
}

func WithNft() RunnerOption {
	return func(callBack func(event *trackapi.PortEvent)) trackapi.PortTracker {
		return &nfttracker.NftPortTracker{CallbackFn: callBack}
	}
}

func NewRunner(options ...RunnerOption) *Runner {
	openPorts := make(map[string]*trackapi.PortEvent)
	return &Runner{options: options, openPorts: openPorts}
}

func (r *Runner) withCacheCallback(callBack func(event *trackapi.PortEvent)) func(event *trackapi.PortEvent) {
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

func (r *Runner) Run(ctx context.Context, callBack func(event *trackapi.PortEvent)) chan error {
	errorCh := make(chan error)

	callback := r.withCacheCallback(callBack)
	go func() {
		for _, opt := range r.options {
			tracker := opt(callback)
			go func() {
				err := tracker.Run(ctx)
				errorCh <- err
			}()
		}
	}()
	return errorCh
}

func key(event *trackapi.PortEvent) string {
	return fmt.Sprintf("%d-%s-%s", event.Protocol, event.Ip.String(), event.Port)
}

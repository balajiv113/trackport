package main

import (
	"context"
	"github.com/balajiv113/trackport/pkg/bpftracker"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"log"
)

func main() {
	callbackFn := func(event *trackapi.PortEvent) {
		log.Print(event)
	}
	portMonitor := bpftracker.NewTracker(callbackFn)
	err := portMonitor.Run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

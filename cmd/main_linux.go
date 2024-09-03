package main

import (
	"context"
	"github.com/balajiv113/trackport"
	"log"
)

func main() {
	callbackFn := func(event *trackport.PortEvent) {
		log.Print(event)
	}
	portMonitor := trackport.NewTracker(callbackFn, true)
	err := portMonitor.Run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

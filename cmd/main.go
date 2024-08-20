package main

import (
	"context"
	"github.com/balajiv113/trackport"
	"log"
)

func main() {
	events := make(chan *trackport.PortEvent)
	go func() {
		for event := range events {
			log.Print(event)
		}
	}()
	portMonitor := trackport.NewTracker(events, true)
	err := portMonitor.Run(context.Background())
	if err != nil {
		log.Fatal(err)
	}
}

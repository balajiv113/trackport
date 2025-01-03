package main

import (
	"context"
	"log"

	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/balajiv113/trackport/pkg/tracker"
)

func main() {
	callbackFn := func(event *trackapi.PortEvent) {
		log.Print(event)
	}
	runner := tracker.NewRunner(tracker.WithBpf(), tracker.WithNft())
	err := runner.Run(context.Background(), callbackFn)
	if err != nil {
		log.Fatal(err)
	}
}

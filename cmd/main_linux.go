package main

import (
	"context"
	"github.com/balajiv113/trackport/pkg/trackapi"
	"github.com/balajiv113/trackport/pkg/tracker"
	"log"
)

func main() {
	callbackFn := func(event *trackapi.PortEvent) {
		log.Print(event)
	}
	runner := tracker.NewRunner(tracker.WithBpf(), tracker.WithNft())
	errCh := runner.Run(context.Background(), callbackFn)
	err := <-errCh
	if err != nil {
		log.Fatal(err)
	}
}

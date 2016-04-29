package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/micro/mdns"
)

func main() {

	serviceTag := "_foobar._tcp"
	if len(os.Args) > 1 {
		serviceTag = os.Args[1]
	}

	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 8)
	defer close(entriesCh)

	go func() {
		for entry := range entriesCh {
			fmt.Printf("Got new entry: %v\n", entry)
		}
	}()

	// Start the lookups
	err := mdns.Lookup(serviceTag, entriesCh)
	if err != nil {
		fmt.Println(err)
	}

	wait()
}

func wait() {
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, os.Kill)
	<-ch
}

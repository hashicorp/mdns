package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cryptix/mdns"
)

func main() {

	// Make a channel for results and start listening
	entriesCh := make(chan *mdns.ServiceEntry, 8)
	defer close(entriesCh)

	go func() {
		for entry := range entriesCh {
			fmt.Printf("Got new entry: %v\n", entry)
		}
	}()

	// Start the lookup
	err := mdns.Lookup("_foobar._tcp", entriesCh)
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

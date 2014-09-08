package main

import (
	"fmt"
	"github.com/poofyleek/mdns"
)

func main() {
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	go func() {
		for entry := range entriesCh {
			fmt.Printf("Got new entry: NAME %s ADDR %v,%v PORT %v INFO %s\n", entry.Name, entry.IPv4Addr, entry.IPv6Addr, entry.Port, entry.Info)
		}
	}()
	mdns.Lookup("_sparkflux._tcp", entriesCh)
	close(entriesCh)

	select{}
}

package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/micro/mdns"
)

func main() {

	serviceTag := "_foobar._tcp"
	if len(os.Args) > 1 {
		serviceTag = os.Args[1]
	}

	// Setup our service export
	host, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	info := []string{"My awesome service"}
	service, err := mdns.NewMDNSService(host, serviceTag, "", "", 8000, nil, info)
	if err != nil {
		log.Fatal(err)
	}

	// Create the mDNS server, defer shutdown
	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		log.Fatal(err)
	}

	defer server.Shutdown()

	wait()
}

func wait() {
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, os.Kill)
	<-ch
}

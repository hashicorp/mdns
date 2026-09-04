// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"log"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestSendQuery_UsesMulticastSocket is a regression for hashicorp/mdns#144:
// sendQuery used to WriteToUDP only on the unicast sockets. Some devices
// ignore queries that do not originate on a multicast socket bound to 5353.
func TestSendQuery_UsesMulticastSocket(t *testing.T) {
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen dest: %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("close dest: %v", err)
		}
	}()

	orig := ipv4Addr
	ipv4Addr = ln.LocalAddr().(*net.UDPAddr)
	t.Cleanup(func() { ipv4Addr = orig })

	mconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen multicast stand-in: %v", err)
	}
	defer func() {
		if err := mconn.Close(); err != nil {
			t.Errorf("close multicast stand-in: %v", err)
		}
	}()

	uconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen unicast stand-in: %v", err)
	}
	// Close the unicast socket so writes on it fail. sendQuery must still
	// deliver the query from the multicast socket.
	if err := uconn.Close(); err != nil {
		t.Fatalf("close unicast: %v", err)
	}

	c := &client{
		ipv4MulticastConn: mconn,
		ipv4UnicastConn:   uconn,
		log:               log.Default(),
	}

	got := make(chan *net.UDPAddr, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 65536)
		_ = ln.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := ln.ReadFromUDP(buf)
		if err != nil {
			errCh <- err
			return
		}
		got <- addr
	}()

	q := new(dns.Msg)
	q.SetQuestion("_foobar._tcp.local.", dns.TypePTR)
	q.RecursionDesired = false
	if err := c.sendQuery(q); err != nil {
		t.Fatalf("sendQuery: %v", err)
	}

	select {
	case addr := <-got:
		mport := mconn.LocalAddr().(*net.UDPAddr).Port
		if addr.Port != mport {
			t.Fatalf("query source port = %d, want multicast socket port %d", addr.Port, mport)
		}
	case err := <-errCh:
		t.Fatalf("did not receive query on destination: %v", err)
	}
}

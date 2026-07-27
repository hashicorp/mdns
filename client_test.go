// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"log"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func testQuestion() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("_foobar._tcp.local.", dns.TypePTR)
	m.RecursionDesired = false
	return m
}

func TestSendQuery_WritesOnMulticastAndUnicast(t *testing.T) {
	// Bind ephemeral UDP sockets and wire them into a client so sendQuery can
	// exercise both multicast and unicast paths without requiring the real
	// 5353 mDNS port.
	mconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen multicast stand-in: %v", err)
	}
	defer mconn.Close()

	uconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen unicast stand-in: %v", err)
	}
	defer uconn.Close()

	c := &client{
		ipv4MulticastConn: mconn,
		ipv4UnicastConn:   uconn,
		log:               log.Default(),
	}

	if err := c.sendQuery(testQuestion()); err != nil {
		t.Fatalf("sendQuery: %v", err)
	}
}

func TestSendQuery_SucceedsIfAnySocketWrites(t *testing.T) {
	// Closed connection always fails WriteToUDP; open one should still make
	// sendQuery return nil (do not surface partial failures).
	bad, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = bad.Close()

	good, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer good.Close()

	c := &client{
		ipv4MulticastConn: bad,
		ipv4UnicastConn:   good,
		log:               log.Default(),
	}
	if err := c.sendQuery(testQuestion()); err != nil {
		t.Fatalf("expected nil when at least one write succeeds, got %v", err)
	}
}

func TestSendQuery_AllWritesFail(t *testing.T) {
	bad, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_ = bad.Close()

	c := &client{
		ipv4UnicastConn: bad,
		log:             log.Default(),
	}
	if err := c.sendQuery(testQuestion()); err == nil {
		t.Fatal("expected error when every write fails")
	}
}

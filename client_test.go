// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestAlias_PreserveIPv4(t *testing.T) {
	inprogress := make(map[string]*ServiceEntry)
	src := "instance._service._tcp.local."
	dst := "host.local."

	ip := net.ParseIP("192.168.1.100")
	dstEntry := ensureName(inprogress, dst)
	dstEntry.AddrV4 = ip
	dstEntry.Addr = ip

	alias(inprogress, src, dst)

	srcEntry := inprogress[src]
	if srcEntry == nil {
		t.Fatalf("expected srcEntry to exist")
	}
	if !srcEntry.AddrV4.Equal(ip) {
		t.Fatalf("expected AddrV4 %v, got %v", ip, srcEntry.AddrV4)
	}
	if !srcEntry.Addr.Equal(ip) {
		t.Fatalf("expected Addr %v, got %v", ip, srcEntry.Addr)
	}
	if inprogress[dst] != srcEntry {
		t.Fatalf("expected inprogress[dst] to point to srcEntry")
	}
}

func TestAlias_PreserveIPv6(t *testing.T) {
	inprogress := make(map[string]*ServiceEntry)
	src := "instance._service._tcp.local."
	dst := "host.local."

	ip := net.ParseIP("fe80::1")
	dstEntry := ensureName(inprogress, dst)
	dstEntry.AddrV6 = ip
	dstEntry.AddrV6IPAddr = &net.IPAddr{IP: ip, Zone: "eth0"}
	dstEntry.Addr = ip

	alias(inprogress, src, dst)

	srcEntry := inprogress[src]
	if srcEntry == nil {
		t.Fatalf("expected srcEntry to exist")
	}
	if !srcEntry.AddrV6.Equal(ip) {
		t.Fatalf("expected AddrV6 %v, got %v", ip, srcEntry.AddrV6)
	}
	if srcEntry.AddrV6IPAddr == nil || !srcEntry.AddrV6IPAddr.IP.Equal(ip) || srcEntry.AddrV6IPAddr.Zone != "eth0" {
		t.Fatalf("expected AddrV6IPAddr with IP %v and Zone eth0, got %v", ip, srcEntry.AddrV6IPAddr)
	}
	if !srcEntry.Addr.Equal(ip) {
		t.Fatalf("expected Addr %v, got %v", ip, srcEntry.Addr)
	}
}

type recordOrderZone struct {
	serviceAddr string
	records     []dns.RR
}

func (z *recordOrderZone) Records(q dns.Question) []dns.RR {
	if q.Name == z.serviceAddr && q.Qtype == dns.TypePTR {
		return z.records
	}
	return nil
}

// TestClient_Lookup_RecordOrder_A_Before_SRV verifies that when an A record
// arrives before the SRV record (PTR -> A -> SRV -> TXT sequence), service discovery
// properly resolves the complete entry with the expected IP address and port.
func TestClient_Lookup_RecordOrder_A_Before_SRV(t *testing.T) {
	serviceName := "_ordercheck._tcp"
	serviceDomain := "local."
	serviceAddr := serviceName + "." + serviceDomain
	instanceName := "mydevice." + serviceAddr
	hostName := "mydevice-host.local."
	expectedIP := net.IPv4(192, 168, 1, 50)
	expectedPort := 8080
	expectedInfo := "model=test"

	records := []dns.RR{
		// 1. PTR record arrives first
		&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   serviceAddr,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ptr: instanceName,
		},
		// 2. A record arrives before SRV record
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   hostName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			A: expectedIP,
		},
		// 3. SRV record arrives after A record
		&dns.SRV{
			Hdr: dns.RR_Header{
				Name:   instanceName,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Target: hostName,
			Port:   uint16(expectedPort),
		},
		// 4. TXT record
		&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   instanceName,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Txt: []string{expectedInfo},
		},
	}

	serv, err := NewServer(&Config{Zone: &recordOrderZone{serviceAddr: serviceAddr, records: records}})
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("failed to shutdown server: %v", err)
		}
	}()

	entries := make(chan *ServiceEntry, 1)
	errCh := make(chan error, 1)
	defer close(errCh)

	go func() {
		select {
		case e := <-entries:
			if e.Name != instanceName {
				errCh <- fmt.Errorf("unexpected Name: got %q, want %q", e.Name, instanceName)
				return
			}
			if !e.AddrV4.Equal(expectedIP) {
				errCh <- fmt.Errorf("unexpected AddrV4: got %v, want %v", e.AddrV4, expectedIP)
				return
			}
			if e.Port != expectedPort {
				errCh <- fmt.Errorf("unexpected Port: got %d, want %d", e.Port, expectedPort)
				return
			}
			if e.Info != expectedInfo {
				errCh <- fmt.Errorf("unexpected Info: got %q, want %q", e.Info, expectedInfo)
				return
			}
			errCh <- nil
		case <-time.After(200 * time.Millisecond):
			errCh <- fmt.Errorf("timed out waiting for complete ServiceEntry")
		}
	}()

	params := &QueryParam{
		Service:     serviceName,
		Domain:      "local",
		Timeout:     100 * time.Millisecond,
		Entries:     entries,
		DisableIPv6: true,
	}
	if err := Query(params); err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("regression check failed: %v", err)
	}
}

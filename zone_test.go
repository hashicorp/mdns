package mdns

import (
	"bytes"
	"github.com/miekg/dns"
	"reflect"
	"testing"
)

func makeService(t *testing.T) *MDNSService {
	m := &MDNSService{
		Instance: "hostname.",
		Service:  "_http._tcp.",
		Port:     80,
		Info:     "Local web server",
		Domain:   "local.",
	}
	if err := m.Init(); err != nil {
		t.Fatalf("err: %v", err)
	}
	return m
}

func TestMDNSService_BadAddr(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "random",
		Qtype: dns.TypeANY,
	}
	recs := s.Records(q)
	if len(recs) != 0 {
		t.Fatalf("bad: %v", recs)
	}
}

func TestMDNSService_ServiceAddr(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "_http._tcp.local.",
		Qtype: dns.TypeANY,
	}
	recs := s.Records(q)
	if len(recs) != 5 {
		t.Fatalf("bad: %v", recs)
	}

	ptr, ok := recs[0].(*dns.PTR)
	if !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if _, ok := recs[1].(*dns.SRV); !ok {
		t.Fatalf("bad: %v", recs[1])
	}
	if _, ok := recs[2].(*dns.A); !ok {
		t.Fatalf("bad: %v", recs[2])
	}
	if _, ok := recs[3].(*dns.AAAA); !ok {
		t.Fatalf("bad: %v", recs[3])
	}
	if _, ok := recs[4].(*dns.TXT); !ok {
		t.Fatalf("bad: %v", recs[4])
	}

	if ptr.Ptr != s.instanceAddr {
		t.Fatalf("bad: %v", recs[0])
	}

	q.Qtype = dns.TypePTR
	recs2 := s.Records(q)
	if !reflect.DeepEqual(recs, recs2) {
		t.Fatalf("no match: %v %v", recs, recs2)
	}
}

func TestMDNSService_InstanceAddr_ANY(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "hostname._http._tcp.local.",
		Qtype: dns.TypeANY,
	}
	recs := s.Records(q)
	if len(recs) != 4 {
		t.Fatalf("bad: %v", recs)
	}
	if _, ok := recs[0].(*dns.SRV); !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if _, ok := recs[1].(*dns.A); !ok {
		t.Fatalf("bad: %v", recs[1])
	}
	if _, ok := recs[2].(*dns.AAAA); !ok {
		t.Fatalf("bad: %v", recs[2])
	}
	if _, ok := recs[3].(*dns.TXT); !ok {
		t.Fatalf("bad: %v", recs[3])
	}
}

func TestMDNSService_InstanceAddr_SRV(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "hostname._http._tcp.local.",
		Qtype: dns.TypeSRV,
	}
	recs := s.Records(q)
	if len(recs) != 3 {
		t.Fatalf("bad: %v", recs)
	}
	srv, ok := recs[0].(*dns.SRV)
	if !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if _, ok := recs[1].(*dns.A); !ok {
		t.Fatalf("bad: %v", recs[1])
	}
	if _, ok := recs[2].(*dns.AAAA); !ok {
		t.Fatalf("bad: %v", recs[2])
	}

	if srv.Port != uint16(s.Port) {
		t.Fatalf("bad: %v", recs[0])
	}
}

func TestMDNSService_InstanceAddr_A(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "hostname._http._tcp.local.",
		Qtype: dns.TypeA,
	}
	recs := s.Records(q)
	if len(recs) != 1 {
		t.Fatalf("bad: %v", recs)
	}
	a, ok := recs[0].(*dns.A)
	if !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if !bytes.Equal(a.A, s.ipv4Addr) {
		t.Fatalf("bad: %v", recs[0])
	}
}

func TestMDNSService_InstanceAddr_AAAA(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "hostname._http._tcp.local.",
		Qtype: dns.TypeAAAA,
	}
	recs := s.Records(q)
	if len(recs) != 1 {
		t.Fatalf("bad: %v", recs)
	}
	a4, ok := recs[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if !bytes.Equal(a4.AAAA, s.ipv6Addr) {
		t.Fatalf("bad: %v", recs[0])
	}
}

func TestMDNSService_InstanceAddr_TXT(t *testing.T) {
	s := makeService(t)
	q := dns.Question{
		Name:  "hostname._http._tcp.local.",
		Qtype: dns.TypeTXT,
	}
	recs := s.Records(q)
	if len(recs) != 1 {
		t.Fatalf("bad: %v", recs)
	}
	txt, ok := recs[0].(*dns.TXT)
	if !ok {
		t.Fatalf("bad: %v", recs[0])
	}
	if txt.Txt[0] != s.Info {
		t.Fatalf("bad: %v", recs[0])
	}
}

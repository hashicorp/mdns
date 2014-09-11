package mdns

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

const (
	// defaultTtl controls how long we set the TTL for records
	defaultTTL = 10
)

// Zone is the interface used to integrate with the server and
// to serve records dynamically
type Zone interface {
	Records(q dns.Question) []dns.RR
}

// MDNSService is used to export a named service by implementing a Zone
type MDNSService struct {
	Instance string // Instance name (e.g. host name)
	Service  string // Service name (e.g. _http._tcp.)
	HostName string // Host machine DNS name
	Port     int    // Service Port
	Info     string // Service info served as a TXT record
	Domain   string // If blank, assumes "local"

	Addr     net.IP // @Deprecated. Service IP

	ipv4Addr net.IP // Host machine IPv4 address
	ipv6Addr net.IP // Host machine IPv6 address

	serviceAddr  string // Fully qualified service address
	instanceAddr string // Fully qualified instance address
}

// Init should be called to setup the internal state
func (m *MDNSService) Init() error {
	// Setup default domain
	if m.Domain == "" {
		m.Domain = "local"
	}

	// Sanity check inputs
	if m.Instance == "" {
		return fmt.Errorf("Missing service instance name")
	}
	if m.Service == "" {
		return fmt.Errorf("Missing service name")
	}
	if m.Addr == nil && m.HostName == nil {
		return fmt.Errorf("Missing service host/address")
	}
	if m.Port == 0 {
		return fmt.Errorf("Missing service port")
	}

	// Get host information
	hostName, err := os.Hostname()
	if err == nil {
		m.HostName = fmt.Sprintf("%s.", m.HostName)

		addrs, err := net.LookupIP(m.GostName)
		if err != nil {
			// Try appending the host domain suffix and lookup again
			// (required for Linux-based hosts)
			tmpHostName := fmt.Sprintf("%s%s.", m.HostName, m.Domain)

			addrs, err = net.LookupIP(tmpHostName)

			if err != nil {
				return fmt.Errorf("Could not determine host IP addresses for %s", m.HostName)
			}
		}

		for i := 0; i < len(addrs); i++ {
			if ipv4 := addrs[i].To4(); ipv4 != nil {
				m.ipv4Addr = addrs[i]
			} else if ipv6 := addrs[i].To16(); ipv6 != nil {
				m.ipv6Addr = addrs[i]
			}
		}
	} else {
		return fmt.Errorf("Could not determine host")
	}

	// Create the full addresses
	m.serviceAddr = fmt.Sprintf("%s.%s.",
		trimDot(m.Service), trimDot(m.Domain))
	m.instanceAddr = fmt.Sprintf("%s.%s",
		trimDot(m.Instance), m.serviceAddr)
	return nil
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

func (m *MDNSService) Records(q dns.Question) []dns.RR {
	switch q.Name {
	case m.serviceAddr:
		return m.serviceRecords(q)
	case m.instanceAddr:
		return m.instanceRecords(q)
	default:
		return nil
	}
}

// serviceRecords is called when the query matches the service name
func (m *MDNSService) serviceRecords(q dns.Question) []dns.RR {
	switch q.Qtype {
	case dns.TypeANY:
		fallthrough
	case dns.TypePTR:
		// Build a PTR response for the service
		rr := &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ptr: m.instanceAddr,
		}
		servRec := []dns.RR{rr}

		// Get the isntance records
		instRecs := m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeANY,
		})

		// Return the service record with the instance records
		return append(servRec, instRecs...)
	default:
		return nil
	}
}

// serviceRecords is called when the query matches the instance name
func (m *MDNSService) instanceRecords(q dns.Question) []dns.RR {
	switch q.Qtype {
	case dns.TypeANY:
		// Get the SRV, which includes A and AAAA
		recs := m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeSRV,
		})

		// Add the TXT record
		recs = append(recs, m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeTXT,
		})...)
		return recs

	case dns.TypeA:
		// Only handle if we have a ipv4 addr
		ipv4 := m.Addr.To4()
		if m.ipv4Addr == nil || ipv4 == nil {
			return nil
		}
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   m.HostName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			A: m.ipv4Addr || ipv4,
		}
		return []dns.RR{a}

	case dns.TypeAAAA:
		// Only handle if we have a ipv6 addr
		ipv6 := m.Addr.To16()
		if m.ipv6Addr == nil || m.Addr.To4() != nil {
			return nil
		}
		a4 := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   m.HostName,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			AAAA: m.ipv6Addr || ipv6,
		}
		return []dns.RR{a4}

	case dns.TypeSRV:
		// Create the SRV Record
		srv := &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Priority: 10,
			Weight:   1,
			Port:     uint16(m.Port),
			Target:   m.HostName,
		}
		recs := []dns.RR{srv}

		// Add the A record
		recs = append(recs, m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeA,
		})...)

		// Add the AAAA record
		recs = append(recs, m.instanceRecords(dns.Question{
			Name:  m.instanceAddr,
			Qtype: dns.TypeAAAA,
		})...)
		return recs

	case dns.TypeTXT:
		txt := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Txt: []string{m.Info},
		}
		return []dns.RR{txt}
	}
	return nil
}

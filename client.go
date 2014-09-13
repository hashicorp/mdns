package mdns

import (
	"code.google.com/p/go.net/ipv4"
	"code.google.com/p/go.net/ipv6"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ServiceEntry is returned after we query for a service
type ServiceEntry struct {
	Name string
	Host string
	AddrV4 net.IP
	AddrV6 net.IP
	Port int
	Info string

	Addr net.IP // @Deprecated

	hasTXT bool
	sent   bool
}

// complete is used to check if we have all the info we need
func (s *ServiceEntry) complete() bool {
	return (s.AddrV4 != nil || s.AddrV6 != nil || s.Addr != nil) && s.Port != 0 && s.hasTXT
}

// QueryParam is used to customize how a Lookup is performed
type QueryParam struct {
	Service   string               // Service to lookup
	Domain    string               // Lookup domain, default "local"
	Timeout   time.Duration        // Lookup timeout, default 1 second
	Interface *net.Interface       // Multicast interface to use
	Entries   chan<- *ServiceEntry // Entries Channel
}

// DefaultParams is used to return a default set of QueryParam's
func DefaultParams(service string) *QueryParam {
	return &QueryParam{
		Service: service,
		Domain:  "local",
		Timeout: time.Second,
		Entries: make(chan *ServiceEntry),
	}
}

// Query looks up a given service, in a domain, waiting at most
// for a timeout before finishing the query. The results are streamed
// to a channel. Sends will not block, so clients should make sure to
// either read or buffer.
func Query(params *QueryParam) error {
	// Create a new client
	client, err := newClient()
	if err != nil {
		return err
	}
	defer client.Close()

	// Set the multicast interface
	if params.Interface != nil {
		if err := client.setInterface(params.Interface); err != nil {
			return err
		}
	}

	// Ensure defaults are set
	if params.Domain == "" {
		params.Domain = "local"
	}
	if params.Timeout == 0 {
		params.Timeout = time.Second
	}

	// Run the query
	return client.query(params)
}

// Lookup is the same as Query, however it uses all the default parameters
func Lookup(service string, entries chan<- *ServiceEntry) error {
	params := DefaultParams(service)
	params.Entries = entries
	return Query(params)
}

// Client provides a query interface that can be used to
// search for service providers using mDNS
type client struct {
	ipv4List *net.UDPConn
	ipv6List *net.UDPConn

	closed    bool
	closedCh  chan struct{}
	closeLock sync.Mutex
}

// NewClient creates a new mdns Client that can be used to query
// for records
func newClient() (*client, error) {
	// Create a IPv4 listener
	ipv4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("[ERR] mdns: Failed to bind to udp4 port: %v", err)
	}
	ipv6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		log.Printf("[ERR] mdns: Failed to bind to udp6 port: %v", err)
	}

	if ipv4 == nil && ipv6 == nil {
		return nil, fmt.Errorf("Failed to bind to any udp port!")
	}

	c := &client{
		ipv4List: ipv4,
		ipv6List: ipv6,
		closedCh: make(chan struct{}),
	}
	return c, nil
}

// Close is used to cleanup the client
func (c *client) Close() error {
	c.closeLock.Lock()
	defer c.closeLock.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	close(c.closedCh)

	if c.ipv4List != nil {
		c.ipv4List.Close()
	}
	if c.ipv6List != nil {
		c.ipv6List.Close()
	}
	return nil
}

// setInterface is used to set the query interface, uses sytem
// default if not provided
func (c *client) setInterface(iface *net.Interface) error {
	p := ipv4.NewPacketConn(c.ipv4List)
	if err := p.SetMulticastInterface(iface); err != nil {
		return err
	}
	p2 := ipv6.NewPacketConn(c.ipv6List)
	if err := p2.SetMulticastInterface(iface); err != nil {
		return err
	}
	return nil
}

// query is used to perform a lookup and stream results
func (c *client) query(params *QueryParam) error {
	// Create the service name
	serviceAddr := fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// Start listening for response packets
	msgCh := make(chan *dns.Msg, 32)
	go c.recv(c.ipv4List, msgCh)
	go c.recv(c.ipv6List, msgCh)

	// Send the query
	m := new(dns.Msg)
	m.SetQuestion(serviceAddr, dns.TypePTR)
	m.RecursionDesired = false
	if err := c.sendQuery(m); err != nil {
		return nil
	}

	// Map the in-progress responses
	inprogress := make(map[string]*ServiceEntry)

	// Listen until we reach the timeout
	finish := time.After(params.Timeout)
	for {
		select {
		case resp := <-msgCh:
			var inp *ServiceEntry
			for _, answer := range resp.Answer {
				switch rr := answer.(type) {
				case *dns.PTR:
					// Create new entry for this
					inp = ensureName(inprogress, rr.Ptr)

				case *dns.SRV:
					// Check for a target mismatch
					if rr.Target != rr.Hdr.Name {
						alias(inprogress, rr.Hdr.Name, rr.Target)
					}

					// Get the port
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Host = rr.Target
					inp.Port = int(rr.Port)

				case *dns.TXT:
					// Pull out the txt
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Info = strings.Join(rr.Txt, "|")
					inp.hasTXT = true

				case *dns.A:
					// Pull out the IP
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.A // @Deprecated
					inp.AddrV4 = rr.A

				case *dns.AAAA:
					// Pull out the IP
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.AAAA // @Deprecated
					inp.AddrV6 = rr.AAAA
				}
			}

			// Check if this entry is complete
			if inp.complete() {
				if inp.sent {
					continue
				}
				inp.sent = true
				select {
				case params.Entries <- inp:
				default:
				}
			} else {
				// Fire off a node specific query
				m := new(dns.Msg)
				m.SetQuestion(inp.Name, dns.TypePTR)
				m.RecursionDesired = false
				if err := c.sendQuery(m); err != nil {
					log.Printf("[ERR] mdns: Failed to query instance %s: %v", inp.Name, err)
				}
			}
		case <-finish:
			return nil
		}
	}
	return nil
}

// sendQuery is used to multicast a query out
func (c *client) sendQuery(q *dns.Msg) error {
	buf, err := q.Pack()
	if err != nil {
		return err
	}
	if c.ipv4List != nil {
		c.ipv4List.WriteTo(buf, ipv4Addr)
	}
	if c.ipv6List != nil {
		c.ipv6List.WriteTo(buf, ipv6Addr)
	}
	return nil
}

// recv is used to receive until we get a shutdown
func (c *client) recv(l *net.UDPConn, msgCh chan *dns.Msg) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for !c.closed {
		n, err := l.Read(buf)
		if err != nil {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			log.Printf("[ERR] mdns: Failed to unpack packet: %v", err)
			continue
		}
		select {
		case msgCh <- msg:
		case <-c.closedCh:
			return
		}
	}
}

// ensureName is used to ensure the named node is in progress
func ensureName(inprogress map[string]*ServiceEntry, name string) *ServiceEntry {
	if inp, ok := inprogress[name]; ok {
		return inp
	}
	inp := &ServiceEntry{
		Name: name,
	}
	inprogress[name] = inp
	return inp
}

// alias is used to setup an alias between two entries
func alias(inprogress map[string]*ServiceEntry, src, dst string) {
	srcEntry := ensureName(inprogress, src)
	inprogress[dst] = srcEntry
}

// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ServiceEntry is returned after we query for a service
type ServiceEntry struct {
	Name         string
	Host         string
	AddrV4       net.IP
	AddrV6       net.IP // @Deprecated
	AddrV6IPAddr *net.IPAddr
	Port         int
	Info         string
	InfoFields   []string

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
	Service             string               // Service to lookup
	Domain              string               // Lookup domain, default "local"
	Timeout             time.Duration        // Lookup timeout, default 1 second
	Interface           *net.Interface       // Multicast interface to use
	Entries             chan<- *ServiceEntry // Entries Channel
	WantUnicastResponse bool                 // Unicast response desired, as per 5.4 in RFC
	DisableIPv4         bool                 // Whether to disable usage of IPv4 for MDNS operations. Does not affect discovered addresses.
	DisableIPv6         bool                 // Whether to disable usage of IPv6 for MDNS operations. Does not affect discovered addresses.
	Logger              *log.Logger          // Optionally provide a *log.Logger to better manage log output.
}

// DefaultParams is used to return a default set of QueryParam's
func DefaultParams(service string) *QueryParam {
	return &QueryParam{
		Service:             service,
		Domain:              "local",
		Timeout:             time.Second,
		Entries:             make(chan *ServiceEntry),
		WantUnicastResponse: false, // TODO(reddaly): Change this default.
		DisableIPv4:         false,
		DisableIPv6:         false,
	}
}

// Query looks up a given service, in a domain, waiting at most
// for a timeout before finishing the query. The results are streamed
// to a channel. Sends will not block, so clients should make sure to
// either read or buffer.
func Query(params *QueryParam) error {
	return QueryContext(context.Background(), params)
}

// QueryContext looks up a given service, in a domain, waiting at most
// for a timeout before finishing the query. The results are streamed
// to a channel. Sends will not block, so clients should make sure to
// either read or buffer. QueryContext will attempt to stop the query
// on cancellation.
func QueryContext(ctx context.Context, params *QueryParam) error {
	if params.Logger == nil {
		params.Logger = log.Default()
	}
	// Queries share one set of long-lived sockets (see sharedConns), and each
	// query reads them with its own receivers, so queries are serialised.
	sharedMu.Lock()
	defer sharedMu.Unlock()

	// A multicast interface pinned by an earlier query cannot be portably
	// reset to the system default (IP_MULTICAST_IF with no interface is
	// EINVAL on some platforms), so a query without an Interface gets a
	// freshly bound socket set rather than inheriting the pin.
	if params.Interface == nil && shared != nil && shared.ifacePinned {
		shared.close()
		shared = nil
	}

	// Create a new client on the shared sockets
	client, err := newClient(!params.DisableIPv4, !params.DisableIPv6, params.Logger)
	if err != nil {
		return err
	}
	defer client.Close()

	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-client.closedCh:
			return
		}
	}()

	// Set the multicast interface
	if params.Interface != nil {
		if err := client.setInterface(params.Interface); err != nil {
			client.markBroken()
			return err
		}
		client.conns.ifacePinned = true
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

// sharedConns are the unicast sockets every query in this process reuses.
//
// Upstream opened fresh sockets for every query. Queries are sent from the
// unicast socket, so each query left from a new ephemeral port and looked
// like a brand-new UDP flow to every other host on the link. Callers that
// query periodically — Consul's go-discover mdns provider runs one per
// retry_join attempt — thereby create an unbounded stream of new flows on
// every LAN host, and hosts that keep per-flow state for the remote endpoints
// of their mDNS socket (macOS content filters do, without ever reclaiming it)
// degrade over time. Keeping the unicast sockets for the life of the process
// keeps the source ports stable: one flow per address family.
//
// The multicast sockets are still opened and closed per query, as upstream
// does: nothing is sent from them, so they never create flows elsewhere, and
// holding a wildcard :5353 socket open between queries with no reader would
// only pin a full receive buffer and could swallow unicast datagrams meant
// for the host's own mDNS responder.
//
// The unicast sockets are replaced after a send or receive error (for
// example the interface they were bound through went away), so the next
// query binds afresh. Queries are unchanged on the wire.
type sharedConns struct {
	v4, v6      bool // what was requested when the set was opened
	ifacePinned bool // a query set a multicast interface on these sockets

	ipv4UnicastConn *net.UDPConn
	ipv6UnicastConn *net.UDPConn
}

var (
	// sharedMu serialises queries and guards shared.
	sharedMu sync.Mutex
	shared   *sharedConns
)

func (s *sharedConns) close() {
	for _, c := range []*net.UDPConn{s.ipv4UnicastConn, s.ipv6UnicastConn} {
		if c != nil {
			c.Close()
		}
	}
}

// Client provides a query interface that can be used to
// search for service providers using mDNS
type client struct {
	use_ipv4 bool
	use_ipv6 bool

	ipv4UnicastConn *net.UDPConn // shared, outlives the client
	ipv6UnicastConn *net.UDPConn // shared, outlives the client

	ipv4MulticastConn *net.UDPConn // per client
	ipv6MulticastConn *net.UDPConn // per client

	conns    *sharedConns
	recvWG   sync.WaitGroup // receivers started by query
	broken   int32          // a socket failed; drop the shared set on Close
	closed   int32
	closedCh chan struct{} // closed by Close; ends query and receivers

	log *log.Logger
}

// NewClient creates a new mdns Client that can be used to query for records.
// It reuses the process-wide unicast sockets, opening them on first use or
// after they were dropped, and opens its own multicast sockets. The caller
// must hold sharedMu.
func newClient(v4 bool, v6 bool, logger *log.Logger) (*client, error) {
	if !v4 && !v6 {
		return nil, fmt.Errorf("Must enable at least one of IPv4 and IPv6 querying")
	}
	if shared != nil && (shared.v4 != v4 || shared.v6 != v6) {
		shared.close()
		shared = nil
	}
	if shared == nil {
		conns, err := openUnicast(v4, v6, logger)
		if err != nil {
			return nil, err
		}
		shared = conns
	}
	uconn4, uconn6 := shared.ipv4UnicastConn, shared.ipv6UnicastConn

	// Establish multicast connections
	var mconn4, mconn6 *net.UDPConn
	var err error
	if uconn4 != nil {
		mconn4, err = net.ListenMulticastUDP("udp4", nil, ipv4Addr)
		if err != nil {
			logger.Printf("[ERR] mdns: Failed to bind to udp4 port: %v", err)
		}
	}
	if uconn6 != nil {
		mconn6, err = net.ListenMulticastUDP("udp6", nil, ipv6Addr)
		if err != nil {
			logger.Printf("[ERR] mdns: Failed to bind to udp6 port: %v", err)
		}
	}
	if mconn4 == nil && mconn6 == nil {
		return nil, fmt.Errorf("failed to bind to any multicast udp port")
	}

	// Check that unicast and multicast connections have been made for IPv4 and IPv6
	// and disable the respective protocol if not.
	use4, use6 := uconn4 != nil && mconn4 != nil, uconn6 != nil && mconn6 != nil
	if !use4 {
		logger.Printf("[INFO] mdns: Failed to listen to both unicast and multicast on IPv4")
		if mconn4 != nil {
			mconn4.Close()
		}
		uconn4, mconn4 = nil, nil
	}
	if !use6 {
		logger.Printf("[INFO] mdns: Failed to listen to both unicast and multicast on IPv6")
		if mconn6 != nil {
			mconn6.Close()
		}
		uconn6, mconn6 = nil, nil
	}
	if !use4 && !use6 {
		return nil, fmt.Errorf("at least one of IPv4 and IPv6 must be enabled for querying")
	}

	c := &client{
		use_ipv4:          use4,
		use_ipv6:          use6,
		ipv4MulticastConn: mconn4,
		ipv6MulticastConn: mconn6,
		ipv4UnicastConn:   uconn4,
		ipv6UnicastConn:   uconn6,
		conns:             shared,
		closedCh:          make(chan struct{}),
		log:               logger,
	}
	return c, nil
}

// openUnicast binds the shared unicast sockets for the requested families.
func openUnicast(v4 bool, v6 bool, logger *log.Logger) (*sharedConns, error) {
	// TODO(reddaly): At least attempt to bind to the port required in the spec.
	var uconn4, uconn6 *net.UDPConn
	var err error
	if v4 {
		uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			logger.Printf("[ERR] mdns: Failed to bind to udp4 port: %v", err)
		}
	}
	if v6 {
		uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
		if err != nil {
			logger.Printf("[ERR] mdns: Failed to bind to udp6 port: %v", err)
		}
	}
	if uconn4 == nil && uconn6 == nil {
		return nil, fmt.Errorf("failed to bind to any unicast udp port")
	}
	return &sharedConns{v4: v4, v6: v6, ipv4UnicastConn: uconn4, ipv6UnicastConn: uconn6}, nil
}

// markBroken records that a socket failed, so Close drops the shared set and
// the next query binds new sockets.
func (c *client) markBroken() {
	atomic.StoreInt32(&c.broken, 1)
}

// Close ends the query: it stops and joins this client's receivers and closes
// its multicast sockets, but keeps the shared unicast sockets (unless a
// socket failed, in which case the shared set is dropped too). The caller
// must hold sharedMu.
func (c *client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		// something else already closed it
		return nil
	}

	c.log.Printf("[INFO] mdns: Closing client (shared unicast sockets kept: v4=%v v6=%v)", c.use_ipv4, c.use_ipv6)
	close(c.closedCh)

	// Unblock receivers parked in ReadFromUDP, wait for them, then clear the
	// deadline on the shared sockets so the next query reads blocking again.
	unicast := []*net.UDPConn{c.ipv4UnicastConn, c.ipv6UnicastConn}
	multicast := []*net.UDPConn{c.ipv4MulticastConn, c.ipv6MulticastConn}
	for _, conn := range append(unicast, multicast...) {
		if conn != nil {
			conn.SetReadDeadline(time.Now())
		}
	}
	c.recvWG.Wait()
	for _, conn := range multicast {
		if conn != nil {
			conn.Close()
		}
	}
	for _, conn := range unicast {
		if conn != nil {
			conn.SetReadDeadline(time.Time{})
		}
	}

	if atomic.LoadInt32(&c.broken) == 1 {
		c.conns.close()
		if shared == c.conns {
			shared = nil
		}
	}
	return nil
}

// setInterface is used to set the query interface, uses system
// default if not provided
func (c *client) setInterface(iface *net.Interface) error {
	if c.use_ipv4 {
		p := ipv4.NewPacketConn(c.ipv4UnicastConn)
		if err := p.SetMulticastInterface(iface); err != nil {
			return err
		}
		p = ipv4.NewPacketConn(c.ipv4MulticastConn)
		if err := p.SetMulticastInterface(iface); err != nil {
			return err
		}
	}
	if c.use_ipv6 {
		p2 := ipv6.NewPacketConn(c.ipv6UnicastConn)
		if err := p2.SetMulticastInterface(iface); err != nil {
			return err
		}
		p2 = ipv6.NewPacketConn(c.ipv6MulticastConn)
		if err := p2.SetMulticastInterface(iface); err != nil {
			return err
		}
	}
	return nil
}

// msgAddr carries the message and source address from recv to message processing.
type msgAddr struct {
	msg *dns.Msg
	src *net.UDPAddr
}

// query is used to perform a lookup and stream results
func (c *client) query(params *QueryParam) error {
	// Create the service name
	serviceAddr := fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// Start listening for response packets
	msgCh := make(chan *msgAddr, 32)
	if c.use_ipv4 {
		c.startRecv(c.ipv4UnicastConn, msgCh)
		c.startRecv(c.ipv4MulticastConn, msgCh)
	}
	if c.use_ipv6 {
		c.startRecv(c.ipv6UnicastConn, msgCh)
		c.startRecv(c.ipv6MulticastConn, msgCh)
	}

	// Send the query
	m := new(dns.Msg)
	m.SetQuestion(serviceAddr, dns.TypePTR)
	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	if params.WantUnicastResponse {
		m.Question[0].Qclass |= 1 << 15
	}
	m.RecursionDesired = false
	if err := c.sendQuery(m); err != nil {
		c.markBroken()
		return err
	}

	// Map the in-progress responses
	inprogress := make(map[string]*ServiceEntry)

	// Track names that belong to the queried service. Only entries
	// reachable from a matching PTR record are processed; this
	// prevents unrelated mDNS responses on the network from
	// polluting the results.
	validNames := make(map[string]bool)

	// Listen until we reach the timeout
	finish := time.After(params.Timeout)
	for {
		select {
		case resp := <-msgCh:
			var inp *ServiceEntry
			for _, answer := range append(resp.msg.Answer, resp.msg.Extra...) {
				switch rr := answer.(type) {
				case *dns.PTR:
					// Only accept PTR records for the service we queried.
					if !strings.EqualFold(rr.Hdr.Name, serviceAddr) {
						continue
					}
					validNames[rr.Ptr] = true
					inp = ensureName(inprogress, rr.Ptr)

				case *dns.SRV:
					if !validNames[rr.Hdr.Name] {
						continue
					}
					// The SRV target (hostname) is also valid for A/AAAA lookups
					validNames[rr.Target] = true
					// Check for a target mismatch
					if rr.Target != rr.Hdr.Name {
						alias(inprogress, rr.Hdr.Name, rr.Target)
					}

					// Get the port
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Host = rr.Target
					inp.Port = int(rr.Port)

				case *dns.TXT:
					if !validNames[rr.Hdr.Name] {
						continue
					}
					// Pull out the txt
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Info = strings.Join(rr.Txt, "|")
					inp.InfoFields = rr.Txt
					inp.hasTXT = true

				case *dns.A:
					if !validNames[rr.Hdr.Name] {
						continue
					}
					// Pull out the IP
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.A // @Deprecated
					inp.AddrV4 = rr.A

				case *dns.AAAA:
					if !validNames[rr.Hdr.Name] {
						continue
					}
					// Pull out the IP
					inp = ensureName(inprogress, rr.Hdr.Name)
					inp.Addr = rr.AAAA   // @Deprecated
					inp.AddrV6 = rr.AAAA // @Deprecated
					inp.AddrV6IPAddr = &net.IPAddr{IP: rr.AAAA}
					// link-local IPv6 addresses must be qualified with a zone (interface). Zone is
					// specific to this machine/network-namespace and so won't be carried in the
					// mDNS message itself. We borrow the zone from the source address of the UDP
					// packet, as the link-local address should be valid on that interface.
					if rr.AAAA.IsLinkLocalUnicast() || rr.AAAA.IsLinkLocalMulticast() {
						inp.AddrV6IPAddr.Zone = resp.src.Zone
					}
				}
			}

			if inp == nil {
				continue
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
					c.log.Printf("[ERR] mdns: Failed to query instance %s: %v", inp.Name, err)
				}
			}
		case <-finish:
			return nil
		case <-c.closedCh: // context cancelled
			return nil
		}
	}
}

// sendQuery is used to multicast a query out
func (c *client) sendQuery(q *dns.Msg) error {
	buf, err := q.Pack()
	if err != nil {
		return err
	}
	if c.ipv4UnicastConn != nil {
		_, err = c.ipv4UnicastConn.WriteToUDP(buf, ipv4Addr)
		if err != nil {
			return err
		}
	}
	if c.ipv6UnicastConn != nil {
		_, err = c.ipv6UnicastConn.WriteToUDP(buf, ipv6Addr)
		if err != nil {
			return err
		}
	}
	return nil
}

// startRecv runs recv for one socket as a tracked receiver of this query.
func (c *client) startRecv(l *net.UDPConn, msgCh chan *msgAddr) {
	if l == nil {
		return
	}
	c.recvWG.Add(1)
	go func() {
		defer c.recvWG.Done()
		c.recv(l, msgCh)
	}()
}

// recv is used to receive until we get a shutdown. Close unblocks it with a
// read deadline; any other read error marks the shared sockets broken (so the
// next query rebinds) instead of spinning on a dead socket.
func (c *client) recv(l *net.UDPConn, msgCh chan *msgAddr) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for atomic.LoadInt32(&c.closed) == 0 {
		n, addr, err := l.ReadFromUDP(buf)

		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}

		if err != nil {
			c.log.Printf("[ERR] mdns: Failed to read packet: %v", err)
			c.markBroken()
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			c.log.Printf("[ERR] mdns: Failed to unpack packet: %v", err)
			continue
		}
		select {
		case msgCh <- &msgAddr{
			msg: msg,
			src: addr,
		}:
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

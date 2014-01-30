package mdns

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"sync"
)

const (
	ipv4mdns = "224.0.0.251"
	ipv6mdns = "ff02::fb"
	mdnsPort = 5353
)

var (
	ipv4Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv4mdns),
		Port: mdnsPort,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   net.ParseIP(ipv6mdns),
		Port: mdnsPort,
	}
)

// Config is used to configure the mDNS server
type Config struct {
	// Zone must be provided to support responding to queries
	Zone Zone
}

// mDNS server is used to listen for mDNS queries and respond if we
// have a matching local record
type Server struct {
	config *Config

	ipv4List *net.UDPConn
	ipv6List *net.UDPConn

	shutdown     bool
	shutdownCh   chan struct{}
	shutdownLock sync.Mutex
}

// NewServer is used to create a new mDNS server from a config
func NewServer(config *Config) (*Server, error) {
	// Create the listeners
	ipv4List, err := net.ListenMulticastUDP("udp4", nil, ipv4Addr)
	if err != nil {
		log.Printf("[ERR] mdns: Failed to start IPv4 listener: %v", err)
	}
	ipv6List, err := net.ListenMulticastUDP("udp6", nil, ipv6Addr)
	if err != nil {
		log.Printf("[ERR] mdns: Failed to start IPv6 listener: %v", err)
	}

	// Check if we have any listener
	if ipv4List == nil && ipv6List == nil {
		return nil, fmt.Errorf("No multicast listeners could be started")
	}

	s := &Server{
		config:     config,
		ipv4List:   ipv4List,
		ipv6List:   ipv6List,
		shutdownCh: make(chan struct{}),
	}
	go s.recv(s.ipv4List)
	go s.recv(s.ipv6List)
	return s, nil
}

// Shutdown is used to shutdown the listener
func (s *Server) Shutdown() error {
	s.shutdownLock.Lock()
	defer s.shutdownLock.Unlock()

	if s.shutdown {
		return nil
	}
	s.shutdown = true
	close(s.shutdownCh)

	if s.ipv4List != nil {
		s.ipv4List.Close()
	}
	if s.ipv6List != nil {
		s.ipv6List.Close()
	}
	return nil
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv(c *net.UDPConn) {
	if c == nil {
		return
	}
	buf := make([]byte, 65536)
	for !s.shutdown {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			continue
		}
		if err := s.parsePacket(buf[:n], from); err != nil {
			log.Printf("[ERR] mdns: Failed to handle query: %v", err)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		log.Printf("[ERR] mdns: Failed to unpack packet: %v", err)
		return err
	}
	return s.handleQuery(&msg, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, from net.Addr) error {
	var resp dns.Msg
	resp.SetReply(query)

	// Handle each question
	if len(query.Question) > 0 {
		if err := s.handleQuestion(query.Question[0], &resp); err != nil {
			log.Printf("[ERR] mdns: failed to handle question %v: %v",
				query.Question[0], err)
		}
	}

	// Check if there is an answer
	if len(resp.Answer) > 0 {
		return s.sendResponse(&resp, from)
	}
	return nil
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, resp *dns.Msg) error {
	// Bail if we have no zone
	if s.config.Zone == nil {
		return nil
	}

	// Add all the query answers
	records := s.config.Zone.Records(q)
	resp.Answer = append(resp.Answer, records...)
	return nil
}

// sendResponse is used to send a response packet
func (s *Server) sendResponse(resp *dns.Msg, from net.Addr) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}
	addr := from.(*net.UDPAddr)
	if addr.IP.To4() != nil {
		_, err = s.ipv4List.WriteToUDP(buf, addr)
		return err
	} else {
		_, err = s.ipv6List.WriteToUDP(buf, addr)
		return err
	}
}

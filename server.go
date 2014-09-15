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

	// Iface if provided binds the multicast listener to the given
	// interface. If not provided, the system default multicase interface
	// is used.
	Iface *net.Interface
}

type MCastListener struct {
	Iface *net.Interface
	Listener *net.UDPConn
	IsIpv6 bool
}

// mDNS server is used to listen for mDNS queries and respond if we
// have a matching local record
type Server struct {
	config *Config

	listeners []*MCastListener

	shutdown     bool
	shutdownCh   chan struct{}
	shutdownLock sync.Mutex
}

func addMulticastListenersForIface(listeners []*MCastListener, iface *net.Interface) []*MCastListener {
	if l, err := net.ListenMulticastUDP("udp4", iface, ipv4Addr); err == nil && l != nil {
		listeners = append(listeners, &MCastListener{
			Iface: iface,
			Listener: l,
			IsIpv6: false,
		})
	}
	if l, err := net.ListenMulticastUDP("udp6", iface, ipv6Addr); err == nil && l != nil {
		listeners = append(listeners, &MCastListener{
			Iface: iface,
			Listener: l,
			IsIpv6: true,
		})
	}
	return listeners
}

// NewServer is used to create a new mDNS server from a config
func NewServer(config *Config) (*Server, error) {

	//fmt.Println("new server, config", config, "zone", config.Zone)

	listeners := make([]*MCastListener, 0)

	if config.Iface != nil {
		listeners = addMulticastListenersForIface(listeners, config.Iface)
	} else {
		if ifaces, err := net.Interfaces(); err != nil {
			return nil, err
		} else {
			for _, iface := range ifaces {
				listeners = addMulticastListenersForIface(listeners, &iface)
			}
		}
	}

	// Check if we have any listener
	if len(listeners) == 0 {
		return nil, fmt.Errorf("No multicast listeners could be started")
	}

	s := &Server{
		config:     config,
		listeners:   listeners,
		shutdownCh: make(chan struct{}),
	}

	for _, l := range listeners {
		go s.recv(l)
	}

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

	for _, l := range s.listeners {
		l.Listener.Close()
	}
	return nil
}

// recv is a long running routine to receive packets from an interface
func (s *Server) recv(l *MCastListener) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)
	for !s.shutdown {
		n, from, err := l.Listener.ReadFrom(buf)
		if err != nil {
			continue
		}
		if err := s.parsePacket(buf[:n], l, from); err != nil {
			log.Printf("[ERR] mdns: Failed to handle query: %v", err)
		}
	}
}

// parsePacket is used to parse an incoming packet
func (s *Server) parsePacket(packet []byte, l *MCastListener, from net.Addr) error {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		log.Printf("[ERR] mdns: Failed to unpack packet: %v", err)
		return err
	}
	return s.handleQuery(&msg, l, from)
}

// handleQuery is used to handle an incoming query
func (s *Server) handleQuery(query *dns.Msg, l *MCastListener, from net.Addr) error {
	var resp dns.Msg
	resp.SetReply(query)
	resp.MsgHdr.Authoritative = true	// testing

	// Handle each question
	if len(query.Question) > 0 {
		for i, _ := range query.Question {
			if err := s.handleQuestion(query.Question[i], from, &resp); err != nil {
				log.Printf("[ERR] mdns: failed to handle question %v: %v",
					query.Question[i], err)
			}
		}
	}

	// Check if there is an answer
	if len(resp.Answer) > 0 {
		return s.sendResponse(&resp, l, from)
	}
	return nil
}

// handleQuestion is used to handle an incoming question
func (s *Server) handleQuestion(q dns.Question, from net.Addr, resp *dns.Msg) error {
	// Bail if we have no zone
	if s.config.Zone == nil {
		return nil
	}

	// Add all the query answers
	records := s.config.Zone.Records(q, from)
	resp.Answer = append(resp.Answer, records...)
	return nil
}

// sendResponse is used to send a response packet
func (s *Server) sendResponse(resp *dns.Msg, l *MCastListener, from net.Addr) error {
	buf, err := resp.Pack()
	if err != nil {
		return err
	}
	addr := from.(*net.UDPAddr)
	_, err = l.Listener.WriteToUDP(buf, addr)
	return err
}

// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"io"
	"log"
	"net"
	"runtime"
	"testing"
	"time"
)

// resetShared drops the process-wide sockets so each test starts clean.
func resetShared(t *testing.T) {
	t.Helper()
	drop := func() {
		sharedMu.Lock()
		if shared != nil {
			shared.close()
			shared = nil
		}
		sharedMu.Unlock()
	}
	drop()
	t.Cleanup(drop)
}

var quiet = log.New(io.Discard, "", 0)

func unicastPort(c *client) int {
	return c.ipv4UnicastConn.LocalAddr().(*net.UDPAddr).Port
}

// waitGoroutines waits for the goroutine count to fall back to at most n.
func waitGoroutines(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > n {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines: %d, want <= %d (receivers leaked)", runtime.NumGoroutine(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestClient_SocketsReusedAcrossQueries is the regression guard: consecutive
// clients must reuse the same sockets (same unicast source port on the wire),
// and closing a client must stop its receivers without closing the sockets.
func TestClient_SocketsReusedAcrossQueries(t *testing.T) {
	resetShared(t)
	sharedMu.Lock()
	defer sharedMu.Unlock()

	base := runtime.NumGoroutine()
	c1, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	port := unicastPort(c1)
	msgCh := make(chan *msgAddr, 32)
	c1.startRecv(c1.ipv4UnicastConn, msgCh)
	c1.startRecv(c1.ipv4MulticastConn, msgCh)
	time.Sleep(20 * time.Millisecond) // receivers parked in ReadFromUDP

	done := make(chan struct{})
	go func() { c1.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return: receivers not unblocked")
	}
	waitGoroutines(t, base)

	// The sockets survived the close and still work.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer probe.Close()
	if _, err := c1.ipv4UnicastConn.WriteToUDP([]byte("x"), probe.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("shared unicast socket unusable after Close: %v", err)
	}

	c2, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Close()
	if c2.ipv4UnicastConn != c1.ipv4UnicastConn {
		t.Fatal("second client opened a new unicast socket")
	}
	if got := unicastPort(c2); got != port {
		t.Fatalf("unicast source port changed: %d -> %d", port, got)
	}

	// A receiver started by the second client reads normally again (the
	// unblocking deadline was cleared).
	c2.startRecv(c2.ipv4UnicastConn, msgCh)
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer sender.Close()
	pkt := []byte{0, 0, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0} // empty DNS response
	if _, err := sender.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatalf("err: %v", err)
	}
	select {
	case <-msgCh:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver on reused socket got nothing (stale read deadline?)")
	}
}

// TestClient_MulticastSocketClosedBetweenQueries: the per-query multicast
// socket (a wildcard :5353 listener) must not outlive the query — held open
// with no reader it would pin a full buffer and could swallow unicast mDNS
// datagrams meant for the host's own responder.
func TestClient_MulticastSocketClosedBetweenQueries(t *testing.T) {
	resetShared(t)
	sharedMu.Lock()
	defer sharedMu.Unlock()

	c, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	mconn := c.ipv4MulticastConn
	if mconn == nil {
		t.Fatal("no multicast socket")
	}
	c.Close()
	if err := mconn.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("multicast socket still open after Close")
	}
	if shared == nil || shared.ipv4UnicastConn == nil {
		t.Fatal("shared unicast socket dropped by a clean Close")
	}
}

// TestClient_BrokenSocketsReplaced: after a socket error the set is dropped on
// Close and the next client binds new sockets.
func TestClient_BrokenSocketsReplaced(t *testing.T) {
	resetShared(t)
	sharedMu.Lock()
	defer sharedMu.Unlock()

	c1, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	old := c1.ipv4UnicastConn
	c1.markBroken()
	c1.Close()
	if shared != nil {
		t.Fatal("broken socket set was kept")
	}
	if _, err := old.WriteToUDP([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Fatal("broken socket set was not closed")
	}
	c2, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer c2.Close()
	if c2.ipv4UnicastConn == old {
		t.Fatal("broken socket reused")
	}
}

// TestClient_ReadErrorMarksBroken: a receiver hitting a non-deadline read
// error stops (no busy loop) and marks the set broken.
func TestClient_ReadErrorMarksBroken(t *testing.T) {
	resetShared(t)
	sharedMu.Lock()
	defer sharedMu.Unlock()

	c, err := newClient(true, false, quiet)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	msgCh := make(chan *msgAddr, 1)
	c.startRecv(c.ipv4UnicastConn, msgCh)
	time.Sleep(20 * time.Millisecond)
	c.ipv4UnicastConn.Close() // socket dies under the receiver
	done := make(chan struct{})
	go func() { c.recvWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not exit on read error")
	}
	c.Close()
	if shared != nil {
		t.Fatal("socket set not dropped after read error")
	}
}

// TestQueryContext_CancelReturnsPromptly: cancelling the context ends the
// query instead of waiting out its timeout. Needs multicast send permission
// (skipped where the platform blocks it, e.g. macOS Local Network privacy).
func TestQueryContext_CancelReturnsPromptly(t *testing.T) {
	resetShared(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err := QueryContext(ctx, &QueryParam{
		Service:     "_nothing._tcp",
		Domain:      "local",
		Timeout:     5 * time.Second,
		Entries:     make(chan *ServiceEntry, 1),
		DisableIPv6: true,
		Logger:      quiet,
	})
	if err != nil {
		t.Skipf("query could not be sent here: %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("cancelled query took %v", el)
	}
}

// TestServer_LookupTwiceSameSockets: two real lookups against a local server
// both succeed and leave from the same unicast port. Needs multicast (run as
// root on macOS).
func TestServer_LookupTwiceSameSockets(t *testing.T) {
	resetShared(t)
	serv, err := NewServer(&Config{Zone: makeServiceWithServiceName(t, "_twice._tcp")})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer serv.Shutdown()

	var ports []int
	for i := 0; i < 2; i++ {
		entries := make(chan *ServiceEntry, 4)
		err := Query(&QueryParam{
			Service:     "_twice._tcp",
			Domain:      "local",
			Timeout:     100 * time.Millisecond,
			Entries:     entries,
			DisableIPv6: true,
			Logger:      quiet,
		})
		if err != nil {
			t.Skipf("query could not be sent here: %v", err)
		}
		select {
		case e := <-entries:
			if e.Name != "hostname._twice._tcp.local." || e.Port != 80 {
				t.Fatalf("lookup %d: wrong entry %+v", i, e)
			}
		default:
			t.Fatalf("lookup %d: no entry", i)
		}
		sharedMu.Lock()
		ports = append(ports, shared.ipv4UnicastConn.LocalAddr().(*net.UDPAddr).Port)
		sharedMu.Unlock()
	}
	if ports[0] != ports[1] {
		t.Fatalf("unicast source port changed between lookups: %v", ports)
	}
}

// TestQueryContext_PinnedInterfaceNotInherited: a query that pinned a
// multicast interface leaves a marked set behind; the next query without an
// Interface must get fresh sockets instead of inheriting the pin.
func TestQueryContext_PinnedInterfaceNotInherited(t *testing.T) {
	resetShared(t)
	sharedMu.Lock()
	c, err := newClient(true, false, quiet)
	if err != nil {
		sharedMu.Unlock()
		t.Fatalf("err: %v", err)
	}
	old := c.ipv4UnicastConn
	c.conns.ifacePinned = true // as if a query had set params.Interface
	c.Close()
	sharedMu.Unlock()

	_ = QueryContext(context.Background(), &QueryParam{
		Service:     "_nothing._tcp",
		Domain:      "local",
		Timeout:     10 * time.Millisecond,
		Entries:     make(chan *ServiceEntry, 1),
		DisableIPv6: true,
		Logger:      quiet,
	})
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if shared != nil && shared.ipv4UnicastConn == old {
		t.Fatal("query without Interface inherited the pinned socket set")
	}
}

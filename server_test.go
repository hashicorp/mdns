package mdns

import (
	"bytes"
	"testing"
	"time"
)

func TestServer_StartStop(t *testing.T) {
	s := makeService(t)
	serv, err := NewServer(&Config{s})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer serv.Shutdown()
}

func TestServer_Lookup(t *testing.T) {
	s := makeService(t)
	s.Service = "_foobar._tcp"
	s.Init()
	serv, err := NewServer(&Config{s})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer serv.Shutdown()

	entries := make(chan *ServiceEntry, 1)
	found := false
	go func() {
		select {
		case e := <-entries:
			if e.Name != "hostname._foobar._tcp.local." {
				t.Fatalf("bad: %v", e)
			}
			if !bytes.Equal(e.Addr.To4(), []byte{127, 0, 0, 1}) {
				t.Fatalf("bad: %v", e)
			}
			if e.Port != 80 {
				t.Fatalf("bad: %v", e)
			}
			if e.Info != "Local web server" {
				t.Fatalf("bad: %v", e)
			}
			found = true

		case <-time.After(80 * time.Millisecond):
			t.Fatalf("timeout")
		}
	}()

	err = LookupDomain("_foobar._tcp", "local", 50*time.Millisecond, entries)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !found {
		t.Fatalf("record not found")
	}
}

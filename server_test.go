package mdns

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
)

func TestServer_StartStop(t *testing.T) {
	s := makeService(t)
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	serv, err := NewServer(logger, &Config{Zone: s})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer serv.Shutdown()
}

func TestServer_Lookup(t *testing.T) {
	logger := log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	serv, err := NewServer(logger, &Config{Zone: makeServiceWithServiceName(t, "_foobar._tcp")})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer serv.Shutdown()

	entries := make(chan *ServiceEntry, 1)
	var found int32 = 0
	go func() {
		select {
		case e := <-entries:
			if e.Name != "hostname._foobar._tcp.local." {
				t.Fatalf("bad: %v", e)
			}
			if e.Port != 80 {
				t.Fatalf("bad: %v", e)
			}
			if e.Info != "Local web server" {
				t.Fatalf("bad: %v", e)
			}
			atomic.StoreInt32(&found, 1)

		case <-time.After(80 * time.Millisecond):
			t.Fatalf("timeout")
		}
	}()

	params := &QueryParam{
		Service: "_foobar._tcp",
		Domain:  "local",
		Timeout: 50 * time.Millisecond,
		Entries: entries,
	}
	err = Query(logger, params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if atomic.LoadInt32(&found) == 0 {
		t.Fatalf("record not found")
	}
}

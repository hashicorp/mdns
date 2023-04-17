// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"testing"
	"time"
)

func TestServer_StartStop(t *testing.T) {
	s := makeService(t)
	serv, err := NewServer(&Config{Zone: s})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := serv.Shutdown(); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestServer_Lookup(t *testing.T) {
	serv, err := NewServer(&Config{Zone: makeServiceWithServiceName(t, "_foobar._tcp")})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer func() {
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()

	entries := make(chan *ServiceEntry, 1)
	errCh := make(chan error, 1)
	defer close(errCh)
	go func() {
		select {
		case e := <-entries:
			if e.Name != "hostname._foobar._tcp.local." {
				errCh <- fmt.Errorf("Entry has the wrong name: %+v", e)
				return
			}
			if e.Port != 80 {
				errCh <- fmt.Errorf("Entry has the wrong port: %+v", e)
				return
			}
			if e.Info != "Local web server" {
				errCh <- fmt.Errorf("Entry as the wrong Info: %+v", e)
				return
			}
			errCh <- nil
		case <-time.After(80 * time.Millisecond):
			errCh <- fmt.Errorf("Timed out waiting for response")
		}
	}()

	params := &QueryParam{
		Service:     "_foobar._tcp",
		Domain:      "local",
		Timeout:     50 * time.Millisecond,
		Entries:     entries,
		DisableIPv6: true,
	}
	err = Query(params)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	err = <-errCh
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

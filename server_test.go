// Copyright IBM Corp. 2014, 2025
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
	entries := make(chan *ServiceEntry, 1)
	errCh := make(chan error, 1)
	defer close(errCh)
	testCases := []struct {
		description string
		checkup     func()
	}{
		{description: "normal case", checkup: func() {
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
		}}, {
			description: "change txt",
			checkup: func() {
				select {
				case e := <-entries:
					if e.Info != "a=a|b=b" {
						errCh <- fmt.Errorf("Entry as the wrong Info: %+v", e)
						return
					}
					errCh <- nil
				case <-time.After(80 * time.Millisecond):
					errCh <- fmt.Errorf("Timed out waiting for response")
				}
			},
		},
	}

	svc := makeServiceWithServiceName(t, "_foobar._tcp")
	serv, err := NewServer(&Config{Zone: svc})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer func() {
		if err := serv.Shutdown(); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	for idx, testCase := range testCases {
		go testCase.checkup()
		if idx == 1 {
			svc.UpdateTXT([]string{"a=a", "b=b"})
		}
		params := &QueryParam{
			Service:     "_foobar._tcp",
			Domain:      "local",
			Timeout:     50 * time.Millisecond,
			Entries:     entries,
			DisableIPv6: true,
		}

		err = Query(params)
		if err != nil {
			t.Fatalf("description: %s, err: %v", testCase.description, err)
		}
		err = <-errCh
		if err != nil {
			t.Fatalf("description: %s, err: %v", testCase.description, err)
		}
	}
}

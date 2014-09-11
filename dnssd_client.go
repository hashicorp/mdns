package mdns

import (
	"net"
	"github.com/miekg/dns"
	"fmt"
	//"time"
)

// ServiceEntry is returned after we query for a service
type ServiceEntry struct {
	Name string
	Addr net.IP
	Port uint16
	Info string

	hasTXT bool
	sent   bool
}

func findTXT(client *client, params *QueryParam, entries chan<- ServiceEntry, service ServiceEntry) {
	//fmt.Println("TXT")
	entries <- service
}

func findSRV(client *client, params *QueryParam, entries chan<- ServiceEntry, service ServiceEntry) {
	seenList := map[string]bool{}
	resultChannel := make(chan dns.RR)
	params.Entries = resultChannel

	go func() {
		for result := range resultChannel {
			if result, ok := result.(*dns.SRV); ok {
				if !seenList[result.Target] {
					seenList[result.Target] = true
					//fmt.Println("SRV: " + result.Target)
					newService := ServiceEntry{
						Name: service.Name,
						Port: result.Port,
					}
					newParams := DefaultParams(service.Name)
					newParams.QueryType = dns.TypeTXT
					findTXT(client, newParams, entries, newService)
				}
			}
		}
	}()

	go client.Query(params)
}




func findPTR(client *client, params *QueryParam, entries chan<- ServiceEntry) {
	seenList := map[string]bool{}
	resultChannel := make(chan dns.RR)
	params.Entries = resultChannel

	go func() {
		for result := range resultChannel {
			if result, ok := result.(*dns.PTR); ok {
				if !seenList[result.Ptr] {
					seenList[result.Ptr] = true
					service := ServiceEntry{
						Name: result.Ptr,
					}
					//fmt.Println("PTR: " + result.Ptr)
					params := DefaultParams(result.Ptr)
					params.QueryType = dns.TypeSRV
					findSRV(client, params, entries, service)
				}
			}
		}
	}()
}

func ResolveService(service string, entries chan<- ServiceEntry) error {
	params := DefaultParams(service)
	params.QueryType = dns.TypePTR

	client, err := NewClient()
	if err != nil {
		fmt.Println(err)
		return err
	}

	findPTR(client, params, entries)
	//processResultsSRV(client, resultCh, entries)


	client.Query(params)
	return nil
}

package mdns

import (
	"net"
	"github.com/miekg/dns"
	"fmt"
	"strings"
)

// ServiceEntry is returned after we query for a service
type ServiceEntry struct {
	ServiceName string
	ServiceInstanceName string
	ServiceHost string
	Priority uint16
	Weight uint16
	Addr net.IP
	Port uint16
	PropertyList map[string]interface{}
}

func findIP(client *client, entries chan<- ServiceEntry, service ServiceEntry) {
	seenList := map[string]bool{}
	resultChannel := make(chan dns.RR)

	go func() {
		for result := range resultChannel {
			if result, ok := result.(*dns.A); ok {
				if !seenList[string(result.A)] {
					seenList[string(result.A)] = true
					newService := ServiceEntry{
						ServiceName: service.ServiceName,
						ServiceInstanceName: service.ServiceInstanceName,
						ServiceHost: service.ServiceHost,
						Port: service.Port,
						Priority: service.Priority,
						Weight: service.Weight,
						PropertyList: service.PropertyList,
						Addr: result.A,
					}

					entries <- newService
				}
			}

			if result, ok := result.(*dns.AAAA); ok {
				if !seenList[string(result.AAAA)] {
					seenList[string(result.AAAA)] = true
					newService := ServiceEntry{
						ServiceName: service.ServiceName,
						ServiceInstanceName: service.ServiceInstanceName,
						ServiceHost: service.ServiceHost,
						Port: service.Port,
						Priority: service.Priority,
						Weight: service.Weight,
						PropertyList: service.PropertyList,
						Addr: result.AAAA,
					}

					entries <- newService
				}
			}
		}
	}()

	params := DefaultParams(service.ServiceHost)
	params.QueryType = dns.TypeA
	params.Entries = resultChannel
	go client.Query(params)

	params = DefaultParams(service.ServiceHost)
	params.QueryType = dns.TypeAAAA
	params.Entries = resultChannel
	go client.Query(params)

}


func parseTXT(items []string) map[string]interface{} {
	propertyList := map[string]interface{}{}

	for _, item := range items {
		if len(item) == 0 {
			continue
		}

		if item[0] == '=' {
			// key cannot start with a '='
			continue
		}

		var key string
		var value interface{}
		for idx, c := range item {
			// Find first instance of '=', everything after is value
			if c == '=' {
				// Keys are case insensitive
				key = strings.ToUpper(string(item[:idx]))
				value = item[idx + 1:]
				break
			} else if idx + 1 == len(item) {
				// If item does not have a '=', interpret as a bool
				key = strings.ToUpper(item)
				value = true
				fmt.Println(key)
				break
			}
		}

		if propertyList[key] == nil {
			// Only the first instance of a key is respected
			propertyList[key] = value
		}
	}

	return propertyList
}

func findTXT(client *client, entries chan<- ServiceEntry, service ServiceEntry) {
	// DNS-SD is required to have a TXT record

	seenList := map[string]bool{}
	resultChannel := make(chan dns.RR)

	params := DefaultParams(service.ServiceInstanceName)
	params.QueryType = dns.TypeTXT
	params.Entries = resultChannel

	go func() {
		for result := range resultChannel {
			if result, ok := result.(*dns.TXT); ok {
				if !seenList[result.Hdr.Name] {
					seenList[result.Hdr.Name] = true
					newService := ServiceEntry{
						ServiceName: service.ServiceName,
						ServiceInstanceName: service.ServiceInstanceName,
						ServiceHost: service.ServiceHost,
						Port: service.Port,
						Priority: service.Priority,
						Weight: service.Weight,
						PropertyList: parseTXT(result.Txt),
					}


					//entries <- newService
					findIP(client, entries, newService)
				}
			}
		}
	}()

	go client.Query(params)

}

func findSRV(client *client, entries chan<- ServiceEntry, service ServiceEntry) {
	seenList := map[string]bool{}
	resultChannel := make(chan dns.RR)

	params := DefaultParams(service.ServiceInstanceName)
	params.QueryType = dns.TypeSRV
	params.Entries = resultChannel

	go func() {
		for result := range resultChannel {
			if result, ok := result.(*dns.SRV); ok {
				if !seenList[result.Target] {
					seenList[result.Target] = true
					newService := ServiceEntry{
						ServiceName: service.ServiceName,
						ServiceInstanceName: service.ServiceInstanceName,
						ServiceHost: result.Target,
						Port: result.Port,
						Priority: result.Priority,
						Weight: result.Weight,
					}
					findTXT(client, entries, newService)
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
						ServiceName: params.RecordName,
						ServiceInstanceName: result.Ptr,
					}
					//fmt.Println("PTR: " + result.Ptr)
					findSRV(client, entries, service)
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

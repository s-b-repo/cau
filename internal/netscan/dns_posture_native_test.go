package netscan

import (
	"errors"
	"reflect"
	"testing"
)

func TestNativeDNSPostureScopedResolvers(t *testing.T) {
	const output = `DNS configuration

resolver #1
  search domain[0] : private.example
  nameserver[0] : 192.0.2.1
  nameserver[1] : 2001:0db8::53

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.1
  nameserver[1] : fe80::53%en0
  nameserver[2] : ::1
  if_index : 11 (en0)
`
	result := nativeDNSPosture(readNativeDNS("scutil --dns", macDNSAddresses(output), false, nil))
	expected := []string{"192.0.2.1", "2001:db8::53", "::1", "fe80::53%en0"}
	if !result.Complete() || result.Stub != "loopback_address_configured" || !reflect.DeepEqual(result.Client.Nameservers, expected) {
		t.Fatalf("resolver addresses were not normalized: %+v", result)
	}
	result.Compare(DNSClientScope, expected)
	if result.Policy.Status != "match" {
		t.Fatalf("comparison failed: %+v", result.Policy)
	}
}

func TestNativeDNSPostureIncompleteQuery(t *testing.T) {
	for _, source := range []DNSResolverSource{
		readNativeDNS("native", []string{"192.0.2.1"}, false, errors.New("query failed")),
		readNativeDNS("native", []string{"192.0.2.1", "invalid"}, false, nil),
		readNativeDNS("native", []string{"192.0.2.1"}, true, nil),
	} {
		result := nativeDNSPosture(source)
		result.Compare(DNSClientScope, []string{"192.0.2.2"})
		check := result.Policy
		if result.Complete() || check.Status != "unknown" || len(check.Missing) != 0 ||
			!reflect.DeepEqual(check.Unexpected, []string{"192.0.2.1"}) {
			t.Fatalf("incomplete query yielded misleading policy evidence: %+v", result)
		}
	}
}

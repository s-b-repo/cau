package netscan

import (
	"strings"
	"testing"
)

func TestDesktopConnections(t *testing.T) {
	sockets, malformed, err := parseWindowsConnections([]byte(`{"rows":[
		{"pid":12,"proto":"tcp","state":"SynSent","local_address":"192.0.2.1","local_port":50000,"remote_address":"::ffff:192.0.2.9","remote_port":443},
		{"pid":12,"proto":"udp","local_address":"::","local_port":53},
		{"pid":12,"proto":"tcp","local_address":"invalid","local_port":443}
	]}`))
	if err != nil || malformed != 1 || len(sockets) != 2 || sockets[0].State != stateSynSent ||
		sockets[0].Remote.IP != "192.0.2.9" || !sockets[1].listening() {
		t.Fatalf("invalid Windows socket snapshot: %+v, malformed=%d, err=%v", sockets, malformed, err)
	}
	fields := []string{"p18", "chelper", "\nf1", "PTCP", "n[2001:db8::1]:8443->[2001:db8::2]:40000", "TST=ESTABLISHED",
		"\nf2", "PUDP", "n*:53", "\np19", "csecond", "\nf6", "PTCP", "n127.0.0.1:8000", "TST=LISTEN", "\n"}
	sockets, malformed = parseMacConnections([]byte(strings.Join(fields, "\x00")))
	if malformed != 0 || len(sockets) != 3 || sockets[0].PID != 18 || sockets[0].Comm != "helper" ||
		sockets[0].Remote != (Endpoint{IP: "2001:db8::2", Port: 40000}) || sockets[0].State != stateEstablished ||
		!sockets[1].listening() || !sockets[2].listening() || sockets[2].PID != 19 {
		t.Fatalf("invalid macOS socket snapshot: %+v, malformed=%d", sockets, malformed)
	}
}

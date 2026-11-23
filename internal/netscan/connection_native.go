package netscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/s-b-repo/cau/internal/desktop"
)

const nativeSocketLimit = 16384

type connectionSnapshot struct {
	source, coverage string
	sockets          []Socket
	warnings         []string
}

func readNativeSockets(opts Options) connectionSnapshot {
	parent := opts.Context
	if parent == nil {
		parent = context.Background() // audit:ok compatibility for callers without a context, bounded below
	}
	ctx, cancel := context.WithTimeout(parent, desktop.Timeout)
	defer cancel()
	return nativeConnections(ctx)
}

func collectedConnections(source string, rows []Socket, malformed int, warned bool, err error) connectionSnapshot {
	result := connectionSnapshot{source: source, sockets: rows, coverage: "visible-sockets"}
	switch {
	case err != nil && len(rows) == 0:
		result.coverage, result.warnings = "unavailable", []string{"native connection query did not complete"}
	case err != nil || malformed > 0 || warned:
		result.coverage, result.warnings = "partial", []string{"native connection output was incomplete"}
	}
	return result
}

type windowsSocket struct {
	PID           int    `json:"pid"`
	Name          string `json:"name"`
	Protocol      string `json:"proto"`
	State         string `json:"state"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
}

func parseWindowsConnections(output []byte) ([]Socket, int, error) {
	var raw struct {
		Rows    []windowsSocket `json:"rows"`
		Partial bool            `json:"partial"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, 0, err
	}
	var rows []Socket
	bad := 0
	if raw.Partial {
		bad++
	}
	for i, item := range raw.Rows {
		if i == nativeSocketLimit {
			bad++
			break
		}
		local, err := nativeEndpoint(item.LocalAddress, item.LocalPort)
		if err != nil || item.PID < 0 {
			bad++
			continue
		}
		row := Socket{PID: item.PID, Comm: item.Name, Proto: item.Protocol, Local: local, Inode: strconv.Itoa(i)}
		switch item.Protocol {
		case "tcp":
			remote, err := nativeEndpoint(item.RemoteAddress, item.RemotePort)
			if err != nil {
				bad++
				continue
			}
			row.Remote, row.State = remote, strings.ToUpper(item.State)
			if row.State == "SYNSENT" {
				row.State = stateSynSent
			}
		case "udp":
		default:
			bad++
			continue
		}
		rows = append(rows, row)
	}
	return rows, bad, nil
}

func nativeEndpoint(address string, port int) (Endpoint, error) {
	if address == "*" {
		address = "0.0.0.0"
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || port < 0 || port > 65535 {
		return Endpoint{}, fmt.Errorf("invalid connection endpoint")
	}
	return Endpoint{IP: ip.WithZone("").Unmap().String(), Port: port}, nil
}

func parseMacConnections(output []byte) ([]Socket, int) {
	var rows []Socket
	var pid int
	var comm string
	var row Socket
	bad := 0
	inFile := false
	save := func() {
		if !inFile {
			return
		}
		if row.Local.IP == "" || (row.Proto != "tcp" && row.Proto != "udp") || row.PID <= 0 {
			bad++
			return
		}
		row.Inode = strconv.Itoa(len(rows))
		rows = append(rows, row)
	}
	for line := range strings.SplitSeq(string(output), "\x00") {
		// lsof separates each field with NUL and adds a newline after each record.
		line = strings.TrimLeft(line, "\r\n")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p', 'f':
			save()
			if len(rows) == nativeSocketLimit {
				return rows, bad + 1
			}
			if line[0] == 'p' {
				var err error
				pid, err = strconv.Atoi(line[1:])
				if err != nil {
					pid = 0
					bad++
				}
				comm = ""
				inFile = false
			} else {
				row = Socket{PID: pid, Comm: comm}
				inFile = true
			}
		case 'c':
			comm = line[1:]
		case 'P':
			row.Proto = strings.ToLower(line[1:])
		case 'T':
			if state, found := strings.CutPrefix(line[1:], "ST="); found {
				row.State = state
			}
		case 'n':
			local, remote, paired := strings.Cut(line[1:], "->")
			var ok bool
			row.Local, ok = parseLsofEndpoint(local)
			if ok && paired {
				row.Remote, ok = parseLsofEndpoint(remote)
			}
			if !ok {
				row.Local = Endpoint{}
			}
		}
	}
	save()
	return rows, bad
}

func parseLsofEndpoint(value string) (Endpoint, bool) {
	address, port, err := net.SplitHostPort(value)
	if err != nil {
		// Some lsof versions omit brackets around IPv6 addresses.
		last := strings.LastIndexByte(value, ':')
		if last < 0 {
			return Endpoint{}, false
		}
		address, port = value[:last], value[last+1:]
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return Endpoint{}, false
	}
	result, err := nativeEndpoint(address, number)
	return result, err == nil
}

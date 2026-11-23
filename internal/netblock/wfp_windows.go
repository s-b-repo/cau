//go:build cgo

package netblock

/*
#cgo LDFLAGS: -lfwpuclnt -liphlpapi -lrpcrt4
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <stdlib.h>

// The Windows SDK declares these identifiers. Some MinGW headers omit them.
static const GUID inbound4 = {0x5926dfc8,0xe3cf,0x4426,{0xa2,0x83,0xdc,0x39,0x3f,0x5d,0x0f,0x9d}};
static const GUID inbound6 = {0x634a869f,0xfc23,0x4b90,{0xb0,0xc1,0xbf,0x62,0x0a,0x36,0xae,0x6f}};
static const GUID outbound4 = {0x09e61aea,0xd214,0x46e2,{0x9b,0x21,0xb2,0x6b,0x0b,0x2f,0x28,0xc8}};
static const GUID outbound6 = {0xe1735bde,0x013f,0x4655,{0xb3,0x51,0xa4,0x9e,0x15,0x76,0x2d,0xf0}};
static const GUID remoteAddress = {0xb235ae9a,0x1d64,0x49b8,{0xa4,0x4c,0x5f,0xf3,0xd9,0x09,0x50,0x45}};
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 1
#endif

static DWORD cau_wfp_open(HANDLE *engine, GUID *sublayer) {
	FWPM_SESSION0 session = {0};
	session.displayData.name = L"CAU endpoint response";
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	session.txnWaitTimeoutInMSec = 2000;
	DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine);
	if (status != 0) return status;
	status = UuidCreate(sublayer);
	if (status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY) {
		FWPM_SUBLAYER0 definition = {0};
		definition.subLayerKey = *sublayer;
		definition.displayData.name = L"CAU temporary peer response";
		definition.weight = 0x8000;
		status = FwpmSubLayerAdd0(*engine, &definition, NULL);
	}
	if (status != 0) FwpmEngineClose0(*engine);
	return status;
}

static DWORD cau_wfp_block(HANDLE engine, const GUID *sublayer, const BYTE *address, BOOL ipv6, UINT64 *ids) {
	FWP_V4_ADDR_AND_MASK v4 = {0};
	FWP_V6_ADDR_AND_MASK v6 = {0};
	FWPM_FILTER_CONDITION0 condition = {0};
	condition.fieldKey = remoteAddress;
	condition.matchType = FWP_MATCH_EQUAL;
	if (ipv6) {
		memcpy(v6.addr, address, sizeof(v6.addr));
		v6.prefixLength = 128;
		condition.conditionValue.type = FWP_V6_ADDR_MASK;
		condition.conditionValue.v6AddrMask = &v6;
	} else {
		v4.addr = ((UINT32)address[0] << 24) | ((UINT32)address[1] << 16) |
			((UINT32)address[2] << 8) | address[3];
		v4.mask = 0xffffffff;
		condition.conditionValue.type = FWP_V4_ADDR_MASK;
		condition.conditionValue.v4AddrMask = &v4;
	}

	FWPM_FILTER0 filter = {0};
	filter.displayData.name = L"CAU temporary peer block";
	filter.subLayerKey = *sublayer;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = &condition;
	filter.action.type = FWP_ACTION_BLOCK;
	DWORD status = FwpmTransactionBegin0(engine, 0);
	if (status != 0) return status;
	filter.layerKey = ipv6 ? inbound6 : inbound4;
	status = FwpmFilterAdd0(engine, &filter, NULL, &ids[0]);
	if (status == 0) {
		filter.layerKey = ipv6 ? outbound6 : outbound4;
		status = FwpmFilterAdd0(engine, &filter, NULL, &ids[1]);
	}
	if (status == 0) status = FwpmTransactionCommit0(engine);
	if (status != 0) FwpmTransactionAbort0(engine);
	return status;
}

static DWORD cau_wfp_release(HANDLE engine, UINT64 first, UINT64 second) {
	DWORD status = FwpmTransactionBegin0(engine, 0);
	if (status != 0) return status;
	status = FwpmFilterDeleteById0(engine, first);
	if (status == 0) status = FwpmFilterDeleteById0(engine, second);
	if (status == 0) status = FwpmTransactionCommit0(engine);
	if (status != 0) FwpmTransactionAbort0(engine);
	return status;
}

static DWORD cau_wfp_filter_status(HANDLE engine, UINT64 id) {
	FWPM_FILTER0 *filter = NULL;
	DWORD status = FwpmFilterGetById0(engine, id, &filter);
	if (filter != NULL) FwpmFreeMemory0((void **)&filter);
	return status;
}

typedef struct {
	BYTE family;
	BYTE address[16];
} cau_peer;

static BOOL cau_append_peer(SOCKET_ADDRESS address, cau_peer *out, ULONG *count, ULONG limit) {
	if (address.lpSockaddr == NULL) return TRUE;
	int family = address.lpSockaddr->sa_family;
	if (family != AF_INET && family != AF_INET6) return TRUE;
	if (*count == limit) return FALSE;
	cau_peer *peer = &out[*count];
	if (family == AF_INET && address.iSockaddrLength >= sizeof(SOCKADDR_IN)) {
		peer->family = 4;
		memcpy(peer->address, &((SOCKADDR_IN *)address.lpSockaddr)->sin_addr, 4);
	} else if (family == AF_INET6 && address.iSockaddrLength >= sizeof(SOCKADDR_IN6)) {
		peer->family = 6;
		memcpy(peer->address, &((SOCKADDR_IN6 *)address.lpSockaddr)->sin6_addr, 16);
	} else {
		return FALSE;
	}
	++*count;
	return TRUE;
}

static DWORD cau_protected_peers(cau_peer *out, ULONG *count, ULONG limit) {
	ULONG size = 15000;
	DWORD status = ERROR_BUFFER_OVERFLOW;
	IP_ADAPTER_ADDRESSES *list = NULL;
	for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
		free(list);
		if (size > 4 * 1024 * 1024) return ERROR_BUFFER_OVERFLOW;
		list = malloc(size); // audit:ok checked before the Windows API writes into it
		if (list == NULL) return ERROR_OUTOFMEMORY;
		status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS |
			GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, list, &size);
	}
	if (status == ERROR_SUCCESS) {
		for (IP_ADAPTER_ADDRESSES *adapter = list; adapter != NULL; adapter = adapter->Next) {
			for (IP_ADAPTER_UNICAST_ADDRESS *p = adapter->FirstUnicastAddress; p != NULL; p = p->Next) {
				if (!cau_append_peer(p->Address, out, count, limit)) goto overflow;
			}
			for (IP_ADAPTER_DNS_SERVER_ADDRESS *p = adapter->FirstDnsServerAddress; p != NULL; p = p->Next) {
				if (!cau_append_peer(p->Address, out, count, limit)) goto overflow;
			}
			for (IP_ADAPTER_GATEWAY_ADDRESS_LH *p = adapter->FirstGatewayAddress; p != NULL; p = p->Next) {
				if (!cau_append_peer(p->Address, out, count, limit)) goto overflow;
			}
		}
	}
	free(list);
	return status;
overflow:
	free(list);
	return ERROR_BUFFER_OVERFLOW;
}
*/
import "C"

import (
	"fmt"
	"net/netip"
	"unsafe"
)

type windowsFilterSession struct {
	engine   C.HANDLE
	sublayer C.GUID
}

func openWFP() (filterSession, error) {
	var engine C.HANDLE
	var sublayer C.GUID
	if status := C.cau_wfp_open(&engine, &sublayer); status != 0 {
		return nil, fmt.Errorf("open Windows Filtering Platform session: 0x%08x", uint32(status))
	}
	return &windowsFilterSession{engine: engine, sublayer: sublayer}, nil
}

func (s *windowsFilterSession) add(ip netip.Addr) ([2]uint64, error) {
	address := ip.AsSlice()
	var ids [2]C.UINT64
	var ipv6 C.BOOL
	if ip.Is6() {
		ipv6 = 1
	}
	status := C.cau_wfp_block(s.engine, &s.sublayer, (*C.BYTE)(unsafe.Pointer(&address[0])), ipv6, &ids[0]) // audit:ok valid IPv4/IPv6 octets and two UINT64 slots passed to a synchronous call
	if status != 0 {
		return [2]uint64{}, fmt.Errorf("add Windows peer filters: 0x%08x", uint32(status))
	}
	return [2]uint64{uint64(ids[0]), uint64(ids[1])}, nil
}

func (s *windowsFilterSession) contains(id uint64) (bool, error) {
	status := uint32(C.cau_wfp_filter_status(s.engine, C.UINT64(id)))
	switch status {
	case 0:
		return true, nil
	case 0x80320003: // FWP_E_FILTER_NOT_FOUND
		return false, nil
	default:
		return false, fmt.Errorf("read Windows peer filter: 0x%08x", status)
	}
}

func (s *windowsFilterSession) remove(ids [2]uint64) error {
	if status := C.cau_wfp_release(s.engine, C.UINT64(ids[0]), C.UINT64(ids[1])); status != 0 {
		return fmt.Errorf("remove Windows peer filters: 0x%08x", uint32(status))
	}
	return nil
}

func (s *windowsFilterSession) close() error {
	if status := C.FwpmEngineClose0(s.engine); status != 0 {
		return fmt.Errorf("close Windows Filtering Platform session: 0x%08x", uint32(status))
	}
	return nil
}

func windowsProtectedAddresses() ([]string, error) {
	var peers [4096]C.cau_peer
	var count C.ULONG
	if status := C.cau_protected_peers(&peers[0], &count, C.ULONG(len(peers))); status != 0 {
		return nil, fmt.Errorf("verify Windows interface, gateway and resolver addresses: 0x%08x", uint32(status))
	}
	var out []string
	for _, peer := range peers[:count] {
		if peer.family == 4 {
			var address [4]byte
			for i := range address {
				address[i] = byte(peer.address[i])
			}
			out = append(out, netip.AddrFrom4(address).String())
		} else {
			var address [16]byte
			for i := range address {
				address[i] = byte(peer.address[i])
			}
			out = append(out, netip.AddrFrom16(address).Unmap().String())
		}
	}
	return out, nil
}

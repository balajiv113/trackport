// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package trackport

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEvent struct {
	Family uint32
	Proto  uint16
	Sport  uint16
	Saddr  uint32
	Dport  uint16
	_      [2]byte
	Daddr  uint32
	Pid    uint16
	Action uint16
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	Inet6BindSk       *ebpf.ProgramSpec `ebpf:"inet6_bind_sk"`
	InetBindSk        *ebpf.ProgramSpec `ebpf:"inet_bind_sk"`
	InetCskAccept     *ebpf.ProgramSpec `ebpf:"inet_csk_accept"`
	InetCskListenStop *ebpf.ProgramSpec `ebpf:"inet_csk_listen_stop"`
	UdpDestroySock    *ebpf.ProgramSpec `ebpf:"udp_destroy_sock"`
	Udpv6DestroySock  *ebpf.ProgramSpec `ebpf:"udpv6_destroy_sock"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
	Ports  *ebpf.MapSpec `ebpf:"ports"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
	Ports  *ebpf.Map `ebpf:"ports"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Events,
		m.Ports,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	Inet6BindSk       *ebpf.Program `ebpf:"inet6_bind_sk"`
	InetBindSk        *ebpf.Program `ebpf:"inet_bind_sk"`
	InetCskAccept     *ebpf.Program `ebpf:"inet_csk_accept"`
	InetCskListenStop *ebpf.Program `ebpf:"inet_csk_listen_stop"`
	UdpDestroySock    *ebpf.Program `ebpf:"udp_destroy_sock"`
	Udpv6DestroySock  *ebpf.Program `ebpf:"udpv6_destroy_sock"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.Inet6BindSk,
		p.InetBindSk,
		p.InetCskAccept,
		p.InetCskListenStop,
		p.UdpDestroySock,
		p.Udpv6DestroySock,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte

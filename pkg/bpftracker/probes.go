package bpftracker

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
	"strings"
)

type FentryOrKprobe struct {
	fentry *ebpf.Program
	kprobe *ebpf.Program
}

func LoadProbes(objs bpfObjects) map[string]FentryOrKprobe {
	return map[string]FentryOrKprobe{
		"inet_csk_accept":      {nil, objs.KprobeInetCskAccept},
		"inet_csk_listen_stop": {nil, objs.KprobeInetCskListenStop},
		"inet_bind":            {nil, objs.KprobeInetBind},
		"inet_bind_exit":       {nil, objs.KretprobeInetBind},
		"inet6_bind":           {nil, objs.KprobeInetBind},
		"inet6_bind_exit":      {nil, objs.KretprobeInetBind},
		"udp_destroy_sock":     {nil, objs.KprobeUdpDestroySock},
		"udpv6_destroy_sock":   {nil, objs.KprobeUdpDestroySock},
	}
}

func RunProbe(funcName string, probe FentryOrKprobe) (link.Link, error) {
	if ok := commonFentryCheck(funcName); probe.fentry != nil && ok {
		logrus.Infof("Binding in fentry")
		return link.AttachTracing(link.TracingOptions{Program: probe.fentry})
	}
	if probe.kprobe != nil {
		if strings.HasSuffix(funcName, "_exit") {
			logrus.Infof("Binding in kretprobe")
			return link.Kretprobe(strings.TrimSuffix(funcName, "_exit"), probe.kprobe, nil)
		}
		logrus.Infof("Binding in kprobe")
		return link.Kprobe(funcName, probe.kprobe, nil)
	}
	return nil, errors.New("both fentry and kprobe not supported")
}

func commonFentryCheck(funcName string) bool {
	if features.HaveProgramType(ebpf.Tracing) != nil {
		return false
	}

	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceFEntry,
		AttachTo:   funcName,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

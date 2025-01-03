package bpftracker

import (
	"errors"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

type FentryOrKprobe struct {
	fentry *ebpf.Program
	kprobe *ebpf.Program
}

func LoadProbes(objs bpfObjects) map[string]FentryOrKprobe {
	return map[string]FentryOrKprobe{
		"inet_csk_listen_start": {objs.FentryInetCskAccept, objs.KprobeInetCskAccept},
		"inet_csk_listen_stop":  {objs.FentryInetCskListenStop, objs.KprobeInetCskListenStop},
		"inet_bind":             {objs.FentryInetBind, objs.KprobeInetBind},
		"inet_bind_exit":        {objs.FexitInetBind, objs.KretprobeInetBind},
		"inet6_bind":            {objs.FentryInet6Bind, objs.KprobeInetBind},
		"inet6_bind_exit":       {objs.FexitInet6Bind, objs.KretprobeInetBind},
		"udp_destroy_sock":      {objs.FentryUdpDestroySock, objs.KprobeUdpDestroySock},
		"udpv6_destroy_sock":    {objs.FentryUdpv6DestroySock, objs.KprobeUdpDestroySock},
	}
}

func RunProbe(funcName string, probe FentryOrKprobe) (link.Link, error) {
	if ok := commonFentryCheck(funcName); probe.fentry != nil && ok {
		logrus.Infof("Binding in fentry")
		return link.AttachTracing(link.TracingOptions{
			Program: probe.fentry,
		})
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

	attachType := ebpf.AttachTraceFEntry
	if strings.HasSuffix(funcName, "_exit") {
		attachType = ebpf.AttachTraceFExit
	}

	spec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: attachType,
		AttachTo:   strings.TrimSuffix(funcName, "_exit"),
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

	traceLink, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}

	traceLink.Close()

	return true
}

package common

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Kprobe struct {
	// meta
	Function string
	Prog     *ebpf.Program
	IsRet    bool

	// state
	conn link.Link
}

func NewKprobe(function string, prog *ebpf.Program) *Kprobe {
	return &Kprobe{
		Function: function,
		Prog:     prog,
	}
}

func NewKretprobe(function string, prog *ebpf.Program) *Kprobe {
	return &Kprobe{
		Function: function,
		Prog:     prog,
		IsRet:    true,
	}
}

func (k *Kprobe) Attach() error {
	var conn link.Link
	var err error

	// establish the link
	if k.IsRet {
		conn, err = link.Kretprobe(k.Function, k.Prog, nil)
	} else {
		conn, err = link.Kprobe(k.Function, k.Prog, nil)
	}

	// set the state
	k.conn = conn

	// return the error
	return err
}

func (k *Kprobe) Detach() error {
	if k.conn == nil {
		return nil
	}

	return k.conn.Close()
}

func (k *Kprobe) ID() string {
	return "kprobe/" + k.Function
}

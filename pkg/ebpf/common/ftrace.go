package common

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Ftrace struct {
	// meta
	Function string
	Prog     *ebpf.Program
	IsExit   bool

	// state
	conn link.Link
}

func NewFentry(function string, prog *ebpf.Program) *Ftrace {
	return &Ftrace{
		Function: function,
		Prog:     prog,
		IsExit:   false,
	}
}

func NewFexit(function string, prog *ebpf.Program) *Ftrace {
	return &Ftrace{
		Function: function,
		Prog:     prog,
		IsExit:   true,
	}
}

func (ft *Ftrace) Attach() error {
	// Establish the link
	conn, err := link.AttachTracing(link.TracingOptions{
		Program: ft.Prog,
	})

	// Set the state
	ft.conn = conn

	// Return the error
	return err
}

func (ft *Ftrace) Detach() error {
	if ft.conn == nil {
		return nil
	}
	return ft.conn.Close()
}

func (ft *Ftrace) ID() string {
	prefix := "fentry"
	if ft.IsExit {
		prefix = "fexit"
	}
	return fmt.Sprintf("%s/%s", prefix, ft.Function)
}

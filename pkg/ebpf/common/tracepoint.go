package common

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Tracepoint struct {
	// meta
	Group string
	Name  string
	Prog  *ebpf.Program

	// state
	conn link.Link
}

func NewTracepoint(group, name string, prog *ebpf.Program) *Tracepoint {
	return &Tracepoint{
		Group: group,
		Name:  name,
		Prog:  prog,
	}
}

func (t *Tracepoint) Attach() error {
	// establish the link
	conn, err := link.Tracepoint(t.Group, t.Name, t.Prog, nil)

	// set the state
	t.conn = conn

	// return the error
	return err
}

func (t *Tracepoint) Detach() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *Tracepoint) ID() string {
	return fmt.Sprintf("tracepoint/%s/%s", t.Group, t.Name)
}

package common

type Probe interface {
	Attach() error
	Detach() error
	ID() string
}

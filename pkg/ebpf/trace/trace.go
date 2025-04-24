package trace

// represents the different bpf components that can be traced.
type QtapComponent uint32

const (
	QtapCa QtapComponent = iota
	QtapDebug
	QtapGotls
	QtapJavassl
	QtapNodetls
	QtapOpenssl
	QtapProcess
	QtapProtocol
	QtapRedirector
	QtapSocket
)

func QtapComponentFromString(s string) (QtapComponent, bool) {
	switch s {
	case "ca":
		return QtapCa, true
	case "debug":
		return QtapDebug, true
	case "gotls":
		return QtapGotls, true
	case "javassl":
		return QtapJavassl, true
	case "nodetls":
		return QtapNodetls, true
	case "openssl":
		return QtapOpenssl, true
	case "process":
		return QtapProcess, true
	case "protocol":
		return QtapProtocol, true
	case "redirector":
		return QtapRedirector, true
	case "socket":
		return QtapSocket, true
	default:
		return 0, false
	}
}

// TraceEvent represents the different types of trace events
type TraceEvent uint64

const (
	TraceMsg TraceEvent = 1 + iota
	TraceAttr
	TraceEnd
)

// TraceAttrType represents the different types of trace attributes
type TraceAttrType uint64

const (
	TraceString TraceAttrType = 1 + iota
	TraceInt
	TraceUint
	TracePointer
	TraceBool
	TraceIP4
	TraceIP6
)

type TraceEventMeta struct {
	Type TraceEvent
	Tsid uint64
}

type TraceMsgEvent struct {
	MsgSize uint32
}

type TraceAttrEvent struct {
	AttrType  TraceAttrType
	TitleSize uint32
	Title     [256]int8
	_         [4]byte // padding
}

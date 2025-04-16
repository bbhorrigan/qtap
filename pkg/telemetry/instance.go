package telemetry

import (
	"os"

	"github.com/rs/xid"
)

// set on init
var instanceID string = xid.New().String()
var hostname string
var configVersion string

func init() {
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
}

func InstanceID() string {
	return instanceID
}

func Hostname() string {
	return hostname
}

func ConfigVersion() string {
	return configVersion
}

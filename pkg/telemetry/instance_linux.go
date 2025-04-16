package telemetry

import (
	"fmt"
	"syscall"

	"go.uber.org/zap"
)

var kernelFields map[string]string
var systemFields map[string]string

// GetSysInfo initializes the global kernel and system field maps
func GetSysInfo() (map[string]map[string]string, error) {
	if kernelFields == nil || systemFields == nil {
		var uname syscall.Utsname
		if err := syscall.Uname(&uname); err != nil {
			return nil, fmt.Errorf("failed to get system information: %w", err)
		}

		kernelFields = map[string]string{
			"name":    int8ToStr(uname.Sysname[:]),
			"release": int8ToStr(uname.Release[:]),
			"version": int8ToStr(uname.Version[:]),
		}

		systemFields = map[string]string{
			"hostname":     int8ToStr(uname.Nodename[:]),
			"architecture": int8ToStr(uname.Machine[:]),
		}
	}

	return map[string]map[string]string{
		"kernel": kernelFields,
		"system": systemFields,
	}, nil
}

// GetSysInfoAsFields returns system information as zap.Fields
func GetSysInfoAsFields() zap.Field {
	sysInfo, err := GetSysInfo()
	if err != nil {
		return zap.Error(err)
	}

	return zap.Any("sysinfo", sysInfo)
}

// int8ToStr converts []int8 to string, stopping at null terminator
func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

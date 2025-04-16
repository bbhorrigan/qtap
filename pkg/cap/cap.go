package cap

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// the magic number for cgroup v2 defined as 0x63677270 in the Linux kernel
const CGROUP2_SUPER_MAGIC = 0x63677270

// Capability represents a Linux capability.
type Capability int

const (
	CAP_IS_MODERN_KERNEL     Capability = iota // is the kernel at least 5.10
	CAP_BPF_PROBE_WRITE_USER                   // allows writing to user memory from eBPF programs.
	CAP_CGROUPS_V2                             // indicates if cgroups v2 is enabled
)

func (c Capability) String() string {
	switch c {
	case CAP_IS_MODERN_KERNEL:
		return "is_modern_kernel"
	case CAP_BPF_PROBE_WRITE_USER:
		return "bpf_probe_write_user"
	case CAP_CGROUPS_V2:
		return "cgroups_v2"
	default:
		return fmt.Sprintf("unknown capability: %d", c)
	}
}

func HasCapability(cap Capability) (bool, error) {
	switch cap {
	case CAP_BPF_PROBE_WRITE_USER:
		return CanBpfProbeWriteUser()
	case CAP_IS_MODERN_KERNEL:
		return IsModernKernel()
	case CAP_CGROUPS_V2:
		return HasCgroupsV2()
	default:
		return false, fmt.Errorf("unknown capability: %s", cap)
	}
}

func CanBpfProbeWriteUser() (bool, error) {
	// read the contents of the lockdown file
	content, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return false, fmt.Errorf("failed to read lockdown file: %w", err)
	}

	// convert content to string and trim whitespace
	lockdownStatus := strings.TrimSpace(string(content))

	// check if the lockdown status contains [none]
	if strings.Contains(lockdownStatus, "[none]") {
		return true, nil
	}

	// if [none] is not present, bpf_probe_write_user is likely not allowed
	return false, nil
}

func IsModernKernel() (bool, error) {
	// Read the kernel version from /proc/sys/kernel/osrelease
	kernelVersion, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false, fmt.Errorf("failed to read kernel version: %w", err)
	}

	// Parse the kernel version string
	version := strings.TrimSpace(string(kernelVersion))
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return false, fmt.Errorf("invalid kernel version format: %s", version)
	}

	// Convert major and minor version to integers
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse major version: %w", err)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, fmt.Errorf("failed to parse minor version: %w", err)
	}

	// Check if the kernel version is 5.10 or later
	if major > 5 || (major == 5 && minor >= 10) {
		return true, nil
	}

	return false, nil
}

func HasCgroupsV2() (bool, error) {
	var statfs syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &statfs); err != nil {
		return false, fmt.Errorf("failed to statfs /sys/fs/cgroup: %w", err)
	}

	return statfs.Type == CGROUP2_SUPER_MAGIC, nil
}
